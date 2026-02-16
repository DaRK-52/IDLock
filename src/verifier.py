from flask import Flask, jsonify, request
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair
import argparse
from typing import Dict, Optional

app = Flask(__name__)

# 初始化配对群
group = PairingGroup('MNT224')


# ==================== Serialization Utilities ====================

def serialize_element(elem) -> str:
    """将群元素序列化为字符串（charm-crypto内部格式）"""
    return group.serialize(elem).decode('utf-8')


def deserialize_element(s: str):
    """将字符串反序列化为群元素（charm-crypto内部格式）"""
    return group.deserialize(s.encode('utf-8'))


def deserialize_pp(data: Dict) -> Dict:
    """反序列化公共参数"""
    result = {
        "g1": deserialize_element(data["g1"]),
        "g2": deserialize_element(data["g2"]),
        "pk": deserialize_element(data["pk"]),
        "n": data["n"],
        "hp": deserialize_element(data["hp"]),
        "H": group.hash,
    }
    for i in range(0, data["n"] + 1):
        result[f"h{i}"] = deserialize_element(data[f"h{i}"])
    return result


# ==================== Verifier Implementation ====================

class Verifier:
    """BBS+ 选择性披露验证者"""

    def __init__(self):
        self.PP: Optional[Dict] = None
        self.policy: Optional[Dict] = None
        self.is_setup = False

    def setup(self, PP: Dict):
        """
        加载公共参数
        Args:
            PP: 与 Issuer 相同的公共参数
        """
        self.PP = PP
        self.is_setup = True
        print("Verifier 已加载公共参数")

    def set_policy(self, policy: Dict):
        """
        设置访问策略
        Args:
            policy: {"m1": "100", "m3": "105"} — 要求公开并匹配的属性
        """
        self.policy = policy
        print(f"访问策略已设置: {policy}")

    def get_policy(self) -> Optional[Dict]:
        """获取当前访问策略"""
        return self.policy

    def verify(self, proof: Dict) -> Dict:
        """
        验证用户的选择性披露证明

        BBS+ 选择性披露验证协议:
            1. 策略检查: 公开属性是否满足访问策略
            2. 配对检查: e(A_bar, g2) == e(A_prime, pk) — 凭证有效性
            3. Schnorr 验证: c == H(A' || A_bar || T' || R3)
            4. DID 验证: u^{z_s} == R3 * v^c — 身份陷门一致性

        proof 结构:
            {
                "disclosed_attrs": {"m1": "100", "m3": "105"},  # 公开属性（字符串值）
                "did_u": G1,         # 用户DID(u, v)中的u
                "did_v": G1,         # 用户DID(u, v)中的v
                "A_prime": G1,       # A' = A ^ r1（随机化凭证）
                "A_bar": G1,         # A_bar = A' ^ sk（配对等式右侧）
                "c": ZR,             # Fiat-Shamir 挑战
                "z_x": ZR,           # x 的响应
                "z_r1": ZR,          # r1 的响应
                "z_s_prime": ZR,     # s * r1 的响应
                "z_s": ZR,           # s 的响应（DID验证: z_s = k_s + c*s）
                "z_hidden": {        # 隐藏属性的响应 {m_i * r1}
                    "m2": ZR,
                    "m4": ZR,
                },
                "R3": G1,            # u^{k_s}，证明 v=u^s 中的 s 与凭证一致
            }

        Returns:
            {"valid": bool, "message": str}
        """
        if not self.is_setup:
            return {"valid": False, "message": "Verifier 未初始化"}
        if self.policy is None:
            return {"valid": False, "message": "访问策略未设置"}

        PP = self.PP
        disclosed_attrs = proof["disclosed_attrs"]

        # ========== Step 1: 检查公开属性是否满足访问策略 ==========
        for attr_key, required_value in self.policy.items():
            if attr_key not in disclosed_attrs:
                return {
                    "valid": False,
                    "message": f"策略要求属性 {attr_key} 公开，但未提供"
                }
            if disclosed_attrs[attr_key] != required_value:
                return {
                    "valid": False,
                    "message": f"属性 {attr_key} 不满足策略: "
                               f"期望 '{required_value}', 收到 '{disclosed_attrs[attr_key]}'"
                }

        # ========== Step 2: 配对检查 e(A_bar, g2) == e(A_prime, pk) ==========
        A_prime = proof["A_prime"]
        A_bar = proof["A_bar"]

        lhs = pair(A_bar, PP["g2"])
        rhs = pair(A_prime, PP["pk"])

        if lhs != rhs:
            return {"valid": False, "message": "配对检查失败，凭证无效"}

        # ========== Step 3: Schnorr 验证 ==========
        c = proof["c"]
        z_x = proof["z_x"]
        z_r1 = proof["z_r1"]
        z_s_prime = proof["z_s_prime"]
        z_s = proof["z_s"]
        z_hidden = proof["z_hidden"]
        R3 = proof["R3"]
        u = proof["did_u"]
        v = proof["did_v"]

        # 计算 B_D = g1 * Π_{j∈D} h_j ^ H(m_j)
        B_D = PP["g1"]
        for attr_key, attr_value in disclosed_attrs.items():
            i = int(attr_key[1:])  # "m1" -> 1
            h_i = PP[f"h{i}"]
            m_j = PP["H"](attr_value, ZR)
            B_D = B_D * (h_i ** m_j)

        # 重算 T' = A'^{-z_x} * B_D^{z_r1} * h0^{z_s'} * Π_{i∈H} h_i^{z_{m_i'}} * A_bar^{-c}
        T_prime = (A_prime ** (-z_x)) * (B_D ** z_r1) * (PP["h0"] ** z_s_prime)

        for attr_key, z_mi in z_hidden.items():
            i = int(attr_key[1:])  # "m2" -> 2
            h_i = PP[f"h{i}"]
            T_prime = T_prime * (h_i ** z_mi)

        T_prime = T_prime * (A_bar ** (-c))

        # 检查 c == H(A' || A_bar || T' || R3)
        challenge_input = (serialize_element(A_prime)
                           + serialize_element(A_bar)
                           + serialize_element(T_prime)
                           + serialize_element(R3))
        c_prime = group.hash(challenge_input, ZR)

        if c != c_prime:
            return {"valid": False, "message": "零知识证明验证失败"}

        # ========== Step 4: DID 验证 — 证明 v = u^s 中的 s 与凭证一致 ==========
        # 验证: u^{z_s} == R3 * v^c
        eq_did_lhs = R3 * (v ** c)
        eq_did_rhs = u ** z_s

        if eq_did_lhs != eq_did_rhs:
            return {"valid": False, "message": "DID 验证失败，身份陷门不一致"}

        return {"valid": True, "message": "验证通过"}


# ==================== Flask API Routes ====================

# 创建 Verifier 实例
verifier = Verifier()


@app.route('/setup', methods=['POST'])
def setup():
    """
    加载公共参数
    POST数据格式: {"pp": {...}}  (与 Issuer /pp 接口返回格式一致)
    """
    data = request.get_json()

    if not data or 'pp' not in data:
        return jsonify({"error": "需要提供 'pp' 字段"}), 400

    try:
        PP = deserialize_pp(data['pp'])
        verifier.setup(PP)
        return jsonify({"message": "公共参数加载成功"}), 201
    except Exception as e:
        return jsonify({"error": f"公共参数反序列化失败: {str(e)}"}), 400


@app.route('/policy', methods=['POST'])
def set_policy():
    """
    设置访问策略
    POST数据格式: {"policy": {"m1": "100", "m3": "105"}}
    """
    if not verifier.is_setup:
        return jsonify({"error": "Verifier 未初始化，请先调用 /setup"}), 400

    data = request.get_json()

    if not data or 'policy' not in data:
        return jsonify({"error": "需要提供 'policy' 字段"}), 400

    verifier.set_policy(data['policy'])
    return jsonify({
        "message": "访问策略已设置",
        "policy": data['policy']
    }), 201


@app.route('/policy', methods=['GET'])
def get_policy():
    """
    查询当前访问策略
    """
    if verifier.policy is None:
        return jsonify({"error": "访问策略未设置"}), 400

    return jsonify({"policy": verifier.policy}), 200


@app.route('/verify', methods=['POST'])
def verify():
    """
    验证用户证明
    POST数据格式:
    {
        "disclosed_attrs": {"m1": "100", "m3": "105"},
        "did_u": "<serialized>",
        "did_v": "<serialized>",
        "A_prime": "<serialized>",
        "A_bar": "<serialized>",
        "c": "<serialized>",
        "z_x": "<serialized>",
        "z_r1": "<serialized>",
        "z_s_prime": "<serialized>",
        "z_s": "<serialized>",
        "R3": "<serialized>",
        "z_hidden": {"m2": "<serialized>", "m4": "<serialized>"}
    }
    """
    if not verifier.is_setup:
        return jsonify({"error": "Verifier 未初始化，请先调用 /setup"}), 400
    if verifier.policy is None:
        return jsonify({"error": "访问策略未设置"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "需要提供证明数据"}), 400

    try:
        proof = {
            "disclosed_attrs": data["disclosed_attrs"],
            "did_u": deserialize_element(data["did_u"]),
            "did_v": deserialize_element(data["did_v"]),
            "A_prime": deserialize_element(data["A_prime"]),
            "A_bar": deserialize_element(data["A_bar"]),
            "c": deserialize_element(data["c"]),
            "z_x": deserialize_element(data["z_x"]),
            "z_r1": deserialize_element(data["z_r1"]),
            "z_s_prime": deserialize_element(data["z_s_prime"]),
            "z_s": deserialize_element(data["z_s"]),
            "R3": deserialize_element(data["R3"]),
            "z_hidden": {
                k: deserialize_element(v) for k, v in data["z_hidden"].items()
            }
        }
    except Exception as e:
        return jsonify({"error": f"证明反序列化失败: {str(e)}"}), 400

    result = verifier.verify(proof)
    status = 200 if result["valid"] else 400
    return jsonify(result), status


@app.route('/', methods=['GET'])
def index():
    """
    API根路径，返回可用端点
    """
    return jsonify({
        "message": "Verifier验证者服务",
        "endpoints": {
            "POST /setup": "加载公共参数 {pp: {...}}",
            "POST /policy": "设置访问策略 {policy: {m1: '100'}}",
            "GET  /policy": "查询当前访问策略",
            "POST /verify": "验证用户证明",
        }
    }), 200


# ==================== Main Entry ====================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Verifier验证者服务')
    parser.add_argument('--port', type=int, default=5003, help='服务端口（默认: 5003）')
    args = parser.parse_args()

    print("=" * 60)
    print("Verifier验证者服务启动中...")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=args.port)
