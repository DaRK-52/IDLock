"""
Verifier 功能测试脚本
测试场景:
  1. 全公开属性 + 策略匹配 → 验证通过
  2. 部分披露 + 策略匹配 → 验证通过
  3. 公开属性不满足策略 → 验证失败
  4. 策略要求的属性未披露 → 验证失败
  5. 伪造的凭证 → 配对检查失败
  6. 篡改的 Schnorr 证明 → 零知识证明验证失败
  7. 无隐藏属性（全部公开） → 验证通过  8. 仅隐藏一个属性 → 验证通过
  9. 伪造 DID（v ≠ u^s）→ DID 验证失败
 10. 篡改 R3 → 零知识证明验证失败"""

from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair
from src.issuer import Issuer, serialize_element
from src.verifier import Verifier

group = PairingGroup('MNT224')


# ==================== Proof Generation (Simulate User) ====================

def generate_disclosure_proof(PP, credential, attr_values, disclosed_indices, did_u, did_v):
    """
    模拟用户端生成 BBS+ 选择性披露证明（含 DID 证明）

    协议:
        1. 随机化凭证: A' = A ^ r1
        2. 计算 A_bar = A'^{-x} * B^{r1} = A'^{sk}
        3. Schnorr + Fiat-Shamir 证明知道 x, r1, s*r1, {m_i*r1}_{i∈H}
        4. DID 证明: R3 = u^{k_s}, z_s = k_s + c*s，证明 v=u^s 中的 s 与凭证一致

    Args:
        PP: 公共参数
        credential: {"A": G1, "x": ZR, "s": ZR}
        attr_values: {"m1": "alice", "m2": "25", ...} — 所有属性字符串值
        disclosed_indices: set of int, e.g., {1, 3} — 要披露的属性索引
        did_u: G1 — DID 中的 u
        did_v: G1 — DID 中的 v = u^s
    Returns:
        proof dict
    """
    A = credential["A"]
    x = credential["x"]
    s = credential["s"]
    n = PP["n"]

    # 将所有属性哈希到 ZR
    messages = {}
    for i in range(1, n + 1):
        messages[i] = PP["H"](attr_values[f"m{i}"], ZR)

    hidden_indices = set(range(1, n + 1)) - disclosed_indices

    # Step 1: 随机化凭证
    r1 = group.random(ZR)
    A_prime = A ** r1

    # B = g1 * h0^s * Π h_i^m_i
    B = PP["g1"] * (PP["h0"] ** s)
    for i in range(1, n + 1):
        B = B * (PP[f"h{i}"] ** messages[i])

    # A_bar = A'^{-x} * B^{r1} = A'^{sk}
    A_bar = (A_prime ** (-x)) * (B ** r1)

    # 秘密值
    s_prime = s * r1
    m_primes = {i: messages[i] * r1 for i in hidden_indices}

    # Step 2: Schnorr 承诺
    k_x = group.random(ZR)
    k_r1 = group.random(ZR)
    k_s_prime = group.random(ZR)
    k_s = group.random(ZR)  # DID 证明用
    k_m_primes = {i: group.random(ZR) for i in hidden_indices}

    # B_D = g1 * Π_{j∈D} h_j^m_j
    B_D = PP["g1"]
    for j in disclosed_indices:
        B_D = B_D * (PP[f"h{j}"] ** messages[j])

    # T = A'^{-k_x} * B_D^{k_r1} * h0^{k_s'} * Π_{i∈H} h_i^{k_{m_i'}}
    T = (A_prime ** (-k_x)) * (B_D ** k_r1) * (PP["h0"] ** k_s_prime)
    for i in hidden_indices:
        T = T * (PP[f"h{i}"] ** k_m_primes[i])

    # R3 = u^{k_s}
    R3 = did_u ** k_s

    # c = H(A' || A_bar || T || R3)
    challenge_input = (serialize_element(A_prime)
                       + serialize_element(A_bar)
                       + serialize_element(T)
                       + serialize_element(R3))
    c = group.hash(challenge_input, ZR)

    # 响应
    z_x = k_x + c * x
    z_r1 = k_r1 + c * r1
    z_s_prime = k_s_prime + c * s_prime
    z_s = k_s + c * s  # DID 响应
    z_hidden = {}
    for i in hidden_indices:
        z_hidden[f"m{i}"] = k_m_primes[i] + c * m_primes[i]

    # 构造公开属性
    disclosed_attrs = {}
    for j in disclosed_indices:
        disclosed_attrs[f"m{j}"] = attr_values[f"m{j}"]

    return {
        "disclosed_attrs": disclosed_attrs,
        "did_u": did_u,
        "did_v": did_v,
        "A_prime": A_prime,
        "A_bar": A_bar,
        "c": c,
        "z_x": z_x,
        "z_r1": z_r1,
        "z_s_prime": z_s_prime,
        "z_s": z_s,
        "R3": R3,
        "z_hidden": z_hidden,
    }


# ==================== Helper ====================

def setup_issuer_and_verifier(n=4):
    """创建 Issuer 和 Verifier，共享公共参数"""
    issuer = Issuer()
    issuer.setup(n=n)
    PP = issuer.PP

    verifier = Verifier()
    verifier.setup(PP)

    return issuer, verifier, PP


def issue_credential(issuer, attr_values):
    """使用 Issuer 颁发全公开属性凭证"""
    attributes = {}
    for key, value in attr_values.items():
        attributes[key] = {"value": value}
    return issuer.issue(attributes)


def generate_did(credential):
    """从凭证生成 DID (u, v)，其中 v = u^s"""
    s = credential["s"]
    u = group.random(G1)
    v = u ** s
    return u, v


# ==================== Test Cases ====================

def test_full_disclosure_policy_match():
    """测试1: 全公开属性 + 策略匹配"""
    print("\n" + "=" * 60)
    print("测试1: 全公开属性 + 策略匹配")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "25", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    # 策略要求所有属性
    verifier.set_policy({"m1": "alice", "m2": "25", "m3": "student"})

    # 生成 DID
    did_u, did_v = generate_did(credential)

    # 全部披露
    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 2, 3}, did_u, did_v)
    result = verifier.verify(proof)

    assert result["valid"], f"验证应通过: {result['message']}"
    print(f"  结果: {result['message']}")
    print("  ✅ 全公开属性验证通过")


def test_partial_disclosure_policy_match():
    """测试2: 部分披露 + 策略匹配"""
    print("\n" + "=" * 60)
    print("测试2: 部分披露（m1, m3公开; m2, m4隐藏）")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=4)

    attr_values = {"m1": "100", "m2": "secret_age", "m3": "105", "m4": "secret_id"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    # 策略只要求 m1 和 m3
    verifier.set_policy({"m1": "100", "m3": "105"})

    # 生成 DID
    did_u, did_v = generate_did(credential)

    # 披露 m1, m3; 隐藏 m2, m4
    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 3}, did_u, did_v)
    result = verifier.verify(proof)

    assert result["valid"], f"验证应通过: {result['message']}"
    assert "m2" not in proof["disclosed_attrs"], "m2 不应被披露"
    assert "m4" not in proof["disclosed_attrs"], "m4 不应被披露"
    print(f"  披露属性: {list(proof['disclosed_attrs'].keys())}")
    print(f"  隐藏属性: {list(proof['z_hidden'].keys())}")
    print(f"  结果: {result['message']}")
    print("  ✅ 部分披露验证通过")


def test_policy_value_mismatch():
    """测试3: 公开属性值不满足策略"""
    print("\n" + "=" * 60)
    print("测试3: 公开属性值不满足策略")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "25", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    # 策略要求 m1 = "bob"，但实际为 "alice"
    verifier.set_policy({"m1": "bob"})

    did_u, did_v = generate_did(credential)
    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 2, 3}, did_u, did_v)
    result = verifier.verify(proof)

    assert not result["valid"], "验证应失败"
    assert "不满足策略" in result["message"]
    print(f"  结果: {result['message']}")
    print("  ✅ 策略不匹配被正确拒绝")


def test_policy_attr_not_disclosed():
    """测试4: 策略要求的属性未披露"""
    print("\n" + "=" * 60)
    print("测试4: 策略要求的属性未披露")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "25", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    # 策略要求 m2 公开
    verifier.set_policy({"m2": "25"})

    # 生成 DID
    did_u, did_v = generate_did(credential)

    # 但只披露 m1, m3（不包含 m2）
    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 3}, did_u, did_v)
    result = verifier.verify(proof)

    assert not result["valid"], "验证应失败"
    assert "未提供" in result["message"]
    print(f"  结果: {result['message']}")
    print("  ✅ 缺少披露属性被正确拒绝")


def test_forged_credential():
    """测试5: 伪造凭证 → 配对检查失败"""
    print("\n" + "=" * 60)
    print("测试5: 伪造凭证")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "25", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    verifier.set_policy({"m1": "alice"})

    # 伪造: 篡改 A
    fake_credential = {
        "A": group.random(G1),  # 随机 A
        "x": credential["x"],
        "s": credential["s"],
    }

    did_u, did_v = generate_did(credential)
    proof = generate_disclosure_proof(PP, fake_credential, attr_values, {1, 2, 3}, did_u, did_v)
    result = verifier.verify(proof)

    assert not result["valid"], "验证应失败"
    assert "配对检查失败" in result["message"]
    print(f"  结果: {result['message']}")
    print("  ✅ 伪造凭证被正确拒绝")


def test_tampered_schnorr_proof():
    """测试6: 篡改 Schnorr 响应 → 零知识证明验证失败"""
    print("\n" + "=" * 60)
    print("测试6: 篡改 Schnorr 响应")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "25", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    verifier.set_policy({"m1": "alice"})

    did_u, did_v = generate_did(credential)
    proof = generate_disclosure_proof(PP, credential, attr_values, {1}, did_u, did_v)

    # 篡改 z_x
    proof["z_x"] = group.random(ZR)
    result = verifier.verify(proof)

    assert not result["valid"], "验证应失败"
    print(f"  结果: {result['message']}")
    print("  ✅ 篡改证明被正确拒绝")


def test_all_disclosed_no_hidden():
    """测试7: 无隐藏属性（全部公开，z_hidden 为空）"""
    print("\n" + "=" * 60)
    print("测试7: 全部属性公开，无隐藏属性")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=2)

    attr_values = {"m1": "100", "m2": "200"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    verifier.set_policy({"m1": "100", "m2": "200"})

    did_u, did_v = generate_did(credential)
    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 2}, did_u, did_v)

    assert len(proof["z_hidden"]) == 0, "z_hidden 应为空"

    result = verifier.verify(proof)
    assert result["valid"], f"验证应通过: {result['message']}"
    print(f"  z_hidden: {proof['z_hidden']}")
    print(f"  结果: {result['message']}")
    print("  ✅ 无隐藏属性验证通过")


def test_single_hidden_attribute():
    """测试8: 仅隐藏一个属性"""
    print("\n" + "=" * 60)
    print("测试8: 仅隐藏一个属性（m2）")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "secret_phone", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    # 策略只要求 m1 和 m3
    verifier.set_policy({"m1": "alice", "m3": "student"})

    # 生成 DID
    did_u, did_v = generate_did(credential)

    # 披露 m1, m3; 隐藏 m2
    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 3}, did_u, did_v)
    result = verifier.verify(proof)

    assert result["valid"], f"验证应通过: {result['message']}"
    assert "m2" in proof["z_hidden"], "m2 应在 z_hidden 中"
    print(f"  隐藏属性: {list(proof['z_hidden'].keys())}")
    print(f"  结果: {result['message']}")
    print("  ✅ 单属性隐藏验证通过")


def test_did_wrong_v():
    """测试9: 伪造 DID — v ≠ u^s"""
    print("\n" + "=" * 60)
    print("测试9: 伪造 DID（v 与凭证中的 s 不一致）")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "25", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    verifier.set_policy({"m1": "alice"})

    # 伪造 DID: v = u^{fake_s}，fake_s ≠ credential["s"]
    u = group.random(G1)
    fake_s = group.random(ZR)
    v = u ** fake_s

    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 2, 3}, u, v)
    result = verifier.verify(proof)

    assert not result["valid"], "验证应失败"
    assert "DID" in result["message"]
    print(f"  结果: {result['message']}")
    print("  ✅ 伪造 DID 被正确拒绝")


def test_did_tampered_R3():
    """测试10: 篡改 R3 → 零知识证明验证失败"""
    print("\n" + "=" * 60)
    print("测试10: 篡改 R3")
    print("=" * 60)

    issuer, verifier, PP = setup_issuer_and_verifier(n=3)

    attr_values = {"m1": "alice", "m2": "25", "m3": "student"}
    credential = issue_credential(issuer, attr_values)
    assert credential is not None

    verifier.set_policy({"m1": "alice"})

    did_u, did_v = generate_did(credential)
    proof = generate_disclosure_proof(PP, credential, attr_values, {1, 2, 3}, did_u, did_v)

    # 篡改 R3
    proof["R3"] = group.random(G1)
    result = verifier.verify(proof)

    assert not result["valid"], "验证应失败"
    print(f"  结果: {result['message']}")
    print("  ✅ 篡改 R3 被正确拒绝")


if __name__ == '__main__':
    print("Verifier 功能测试")
    print("=" * 60)

    test_full_disclosure_policy_match()
    test_partial_disclosure_policy_match()
    test_policy_value_mismatch()
    test_policy_attr_not_disclosed()
    test_forged_credential()
    test_tampered_schnorr_proof()
    test_all_disclosed_no_hidden()
    test_single_hidden_attribute()
    test_did_wrong_v()
    test_did_tampered_R3()

    print("\n" + "=" * 60)
    print("全部测试通过 ✅")
    print("=" * 60)
