"""
Issuer 功能测试脚本
测试场景:
  1. 全公开属性颁发
  2. 全盲属性颁发
  3. 混合属性颁发（公开 + 盲）
  4. 错误的零知识证明（应颁发失败）
  5. BBS+ 签名验证
"""

from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair
from src.issuer import Issuer, serialize_element, deserialize_element

group = PairingGroup('MNT224')


def generate_nizk_proof(h_i, m_i):
    """
    用户端生成 NIZK 证明
    证明知道 m_i 使得 commitment = h_i ^ m_i

    步骤:
        1. 计算 commitment = h_i ^ m_i
        2. 选随机 r ∈ ZR, 计算 R = h_i ^ r
        3. c = H(h_i || commitment || R)
        4. z = r + c * m_i
        5. 返回 (commitment, {R, z})
    """
    commitment = h_i ** m_i
    r = group.random(ZR)
    R = h_i ** r

    challenge_input = serialize_element(h_i) + serialize_element(commitment) + serialize_element(R)
    c = group.hash(challenge_input, ZR)

    z = r + c * m_i

    return commitment, {"R": R, "z": z}


def verify_bbs_signature(PP, credential, messages):
    """
    验证 BBS+ 签名: e(A, g2^x * pk) == e(g1 * h0^s * Π h_i^m_i, g2)
    """
    A = credential["A"]
    x = credential["x"]
    s = credential["s"]

    g1, g2, pk, h0 = PP["g1"], PP["g2"], PP["pk"], PP["h0"]

    # 左边: e(A, g2^x * pk)
    lhs = pair(A, (g2 ** x) * pk)

    # 右边: e(g1 * h0^s * Π h_i^m_i, g2)
    rhs_base = g1 * (h0 ** s)
    for i, m_i in enumerate(messages, 1):
        rhs_base = rhs_base * (PP[f"h{i}"] ** m_i)
    rhs = pair(rhs_base, g2)

    return lhs == rhs


def test_all_open():
    """测试1: 全公开属性颁发"""
    print("\n" + "=" * 60)
    print("测试1: 全公开属性颁发")
    print("=" * 60)

    issuer = Issuer()
    issuer.setup(n=3)
    PP = issuer.PP

    attributes = {
        "m1": {"value": "alice"},
        "m2": {"value": "25"},
        "m3": {"value": "student"},
    }

    credential = issuer.issue(attributes)
    assert credential is not None, "颁发失败!"

    print(f"  A = {credential['A']}")
    print(f"  x = {credential['x']}")
    print(f"  s = {credential['s']}")

    # 验证签名
    messages = [PP["H"]("alice", ZR), PP["H"]("25", ZR), PP["H"]("student", ZR)]
    valid = verify_bbs_signature(PP, credential, messages)
    assert valid, "签名验证失败!"
    print("  ✅ BBS+ 签名验证通过")


def test_all_blind():
    """测试2: 全盲属性颁发"""
    print("\n" + "=" * 60)
    print("测试2: 全盲属性颁发")
    print("=" * 60)

    issuer = Issuer()
    issuer.setup(n=3)
    PP = issuer.PP

    # 用户端: 生成盲属性和 NIZK 证明
    m1 = PP["H"]("alice", ZR)
    m2 = PP["H"]("25", ZR)
    m3 = PP["H"]("student", ZR)

    c1, proof1 = generate_nizk_proof(PP["h1"], m1)
    c2, proof2 = generate_nizk_proof(PP["h2"], m2)
    c3, proof3 = generate_nizk_proof(PP["h3"], m3)

    attributes = {
        "m1": {"commitment": c1, "proof": proof1},
        "m2": {"commitment": c2, "proof": proof2},
        "m3": {"commitment": c3, "proof": proof3},
    }

    credential = issuer.issue(attributes)
    assert credential is not None, "颁发失败!"

    print(f"  A = {credential['A']}")
    print(f"  x = {credential['x']}")
    print(f"  s = {credential['s']}")

    # 验证签名
    messages = [m1, m2, m3]
    valid = verify_bbs_signature(PP, credential, messages)
    assert valid, "签名验证失败!"
    print("  ✅ BBS+ 签名验证通过")


def test_mixed():
    """测试3: 混合属性颁发（公开 + 盲）"""
    print("\n" + "=" * 60)
    print("测试3: 混合属性颁发（m1公开, m2盲, m3公开）")
    print("=" * 60)

    issuer = Issuer()
    issuer.setup(n=3)
    PP = issuer.PP

    # m2 为盲属性
    m2 = PP["H"]("25", ZR)
    c2, proof2 = generate_nizk_proof(PP["h2"], m2)

    attributes = {
        "m1": {"value": "alice"},
        "m2": {"commitment": c2, "proof": proof2},
        "m3": {"value": "student"},
    }

    credential = issuer.issue(attributes)
    assert credential is not None, "颁发失败!"

    print(f"  A = {credential['A']}")
    print(f"  x = {credential['x']}")
    print(f"  s = {credential['s']}")

    # 验证签名
    messages = [PP["H"]("alice", ZR), m2, PP["H"]("student", ZR)]
    valid = verify_bbs_signature(PP, credential, messages)
    assert valid, "签名验证失败!"
    print("  ✅ BBS+ 签名验证通过")


def test_invalid_proof():
    """测试4: 错误的零知识证明（应颁发失败）"""
    print("\n" + "=" * 60)
    print("测试4: 错误的零知识证明")
    print("=" * 60)

    issuer = Issuer()
    issuer.setup(n=2)
    PP = issuer.PP

    # 用真实的 m1 生成证明，但用错误的 commitment
    m1_real = PP["H"]("alice", ZR)
    m1_fake = PP["H"]("bob", ZR)

    # 用 fake 值生成 commitment，但用 real 值生成证明 → 不匹配
    fake_commitment = PP["h1"] ** m1_fake
    r = group.random(ZR)
    R = PP["h1"] ** r
    challenge_input = serialize_element(PP["h1"]) + serialize_element(fake_commitment) + serialize_element(R)
    c = group.hash(challenge_input, ZR)
    z = r + c * m1_real  # 使用真实值计算 z，但 commitment 是 fake 的

    attributes = {
        "m1": {"commitment": fake_commitment, "proof": {"R": R, "z": z}},
        "m2": {"value": "25"},
    }

    credential = issuer.issue(attributes)
    assert credential is None, "应该颁发失败!"
    print("  ✅ 错误证明被正确拒绝")


if __name__ == '__main__':
    print("Issuer 功能测试")
    print("=" * 60)

    test_all_open()
    test_all_blind()
    test_mixed()
    test_invalid_proof()

    print("\n" + "=" * 60)
    print("全部测试通过 ✅")
    print("=" * 60)
