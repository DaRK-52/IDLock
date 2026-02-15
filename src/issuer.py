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


def serialize_pp(PP: Dict) -> Dict:
    """序列化公共参数为可JSON传输的格式"""
    result = {
        "g1": serialize_element(PP["g1"]),
        "g2": serialize_element(PP["g2"]),
        "pk": serialize_element(PP["pk"]),
        "n": PP["n"],
        "hp": serialize_element(PP["hp"]),
    }
    for i in range(0, PP["n"] + 1):
        result[f"h{i}"] = serialize_element(PP[f"h{i}"])
    return result


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


# ==================== Issuer Implementation ====================

class Issuer:
    """BBS+签名颁发者"""

    def __init__(self):
        self.PP: Optional[Dict] = None
        self.sk = None
        self.is_setup = False

    def setup(self, n: int = 1) -> Dict:
        """
        初始化颁发者
        Args:
            n: 属性数量上限
        Returns:
            PP: 公共参数
        """
        g1, g2 = group.random(G1), group.random(G2)
        sk = group.random(ZR)
        pk = g2 ** sk
        hp = group.random(G1)

        PP = {
            "g1": g1,
            "g2": g2,
            "pk": pk,
            "n": n,
            "hp": hp,
            "H": group.hash,
        }
        for i in range(0, n + 1):
            h = group.random(G1)
            PP[f"h{i}"] = h

        self.PP = PP
        self.sk = sk
        self.is_setup = True

        print(f"Issuer已初始化，属性数量上限: {n}")
        return PP

    def verify_nizk(self, h_i, commitment, proof: Dict) -> bool:
        """
        验证盲属性的非交互式零知识证明（Schnorr + Fiat-Shamir）
        证明用户知道 m_i 使得 commitment = h_i ^ m_i

        验证过程:
            1. 由证明中的 R = h_i ^ r_i 和 commitment 计算 c = H(h_i || commitment || R)
            2. 检查 h_i ^ z == commitment ^ c * R

        Args:
            h_i: 属性对应的公共基
            commitment: 承诺值 h_i ^ m_i
            proof: {"R": G1 (h_i ^ r_i), "z": ZR (r_i + c * m_i)}
        Returns:
            bool: 证明是否有效
        """
        R = proof["R"]
        z = proof["z"]

        # 计算挑战值 c = H(h_i || commitment || R)
        challenge_input = serialize_element(h_i) + serialize_element(commitment) + serialize_element(R)
        c = group.hash(challenge_input, ZR)

        # 验证 h_i ^ z == commitment ^ c * R
        lhs = h_i ** z
        rhs = (commitment ** c) * R

        return lhs == rhs

    def issue(self, attributes: Dict) -> Optional[Dict]:
        """
        统一颁发接口，支持普通属性和盲属性混合颁发

        每个属性 m_i 有两种提交方式:
        - 公开属性: {"value": str}
            → issuer 直接计算 h_i * H(value)
        - 盲属性:   {"commitment": G1, "proof": {"R": G1, "z": ZR}}
            → issuer 验证 NIZK 后直接使用承诺值 commitment = h_i ^ m_i

        Args:
            attributes: {
                "m1": {"value": "attr1"},                                     # 公开
                "m2": {"commitment": G1_elem, "proof": {"R": G1, "z": ZR}},  # 盲属性
                ...
            }
        Returns:
            Credential: {"A": G1, "x": ZR, "s": ZR} 或 None（验证失败）
        """
        if not self.is_setup:
            return None

        PP = self.PP
        g1, h0 = PP["g1"], PP["h0"]
        x, s = group.random(ZR), group.random(ZR)

        # 计算 A = g1 + h0*s
        A = g1 * (h0 ** s)

        # 遍历所有属性
        for i in range(1, PP["n"] + 1):
            key = f"m{i}"
            h_i = PP[f"h{i}"]

            if key not in attributes:
                return None  # 缺少属性

            attr = attributes[key]

            if "value" in attr:
                # 公开属性: 直接哈希计算
                m_i = PP["H"](attr["value"], ZR)
                A = A * (h_i ** m_i)

            elif "commitment" in attr and "proof" in attr:
                # 盲属性: 先验证 NIZK
                commitment = attr["commitment"]
                proof = attr["proof"]

                if not self.verify_nizk(h_i, commitment, proof):
                    print(f"属性 {key} 的零知识证明验证失败")
                    return None

                # 验证通过，直接使用承诺值（commitment = h_i ^ m_i）
                A = A * commitment

            else:
                return None  # 格式错误

        # A = A ^ (1 / (sk + x))
        A = A ** (1 / (self.sk + x))

        credential = {
            "A": A,
            "x": x,
            "s": s,
        }

        return credential


# ==================== Flask API Routes ====================

# 创建 Issuer 实例（延迟初始化，在 main 中通过命令行参数设定）
issuer = Issuer()


@app.route('/pp', methods=['GET'])
def get_pp():
    """
    获取公共参数
    """
    if not issuer.is_setup:
        return jsonify({"error": "Issuer尚未初始化，请先调用 /setup"}), 400

    return jsonify({
        "pp": serialize_pp(issuer.PP)
    }), 200


@app.route('/issue', methods=['POST'])
def issue():
    """
    颁发凭证（统一接口，支持公开属性与盲属性混合）
    POST数据格式:
    {
        "attributes": {
            "m1": {"value": "alice"},                                           # 公开属性
            "m2": {"commitment": "<base64>", "proof": {"R": "<base64>", "z": "<base64>"}},  # 盲属性
            ...
        }
    }
    """
    if not issuer.is_setup:
        return jsonify({"error": "Issuer尚未初始化，请先调用 /setup"}), 400

    data = request.get_json()

    if not data or 'attributes' not in data:
        return jsonify({"error": "需要提供 'attributes' 字段"}), 400

    raw_attrs = data['attributes']

    # 检查属性数量
    if len(raw_attrs) != issuer.PP["n"]:
        return jsonify({
            "error": f"属性数量不匹配，期望 {issuer.PP['n']}，收到 {len(raw_attrs)}"
        }), 400

    # 反序列化属性
    attributes = {}
    for i in range(1, issuer.PP["n"] + 1):
        key = f"m{i}"
        if key not in raw_attrs:
            return jsonify({"error": f"缺少属性 {key}"}), 400

        attr = raw_attrs[key]

        if "value" in attr:
            # 公开属性，直接传递
            attributes[key] = {"value": attr["value"]}

        elif "commitment" in attr and "proof" in attr:
            # 盲属性，反序列化群元素
            try:
                commitment = deserialize_element(attr["commitment"])
                proof = {
                    "R": deserialize_element(attr["proof"]["R"]),
                    "z": deserialize_element(attr["proof"]["z"]),
                }
                attributes[key] = {
                    "commitment": commitment,
                    "proof": proof,
                }
            except Exception as e:
                return jsonify({"error": f"属性 {key} 反序列化失败: {str(e)}"}), 400
        else:
            return jsonify({
                "error": f"属性 {key} 格式错误，需要 'value' 或 'commitment'+'proof'"
            }), 400

    # 颁发凭证
    credential = issuer.issue(attributes)

    if credential is None:
        return jsonify({"error": "凭证颁发失败，零知识证明验证不通过或参数错误"}), 400

    return jsonify({
        "message": "凭证颁发成功",
        "credential": {
            "A": serialize_element(credential["A"]),
            "x": serialize_element(credential["x"]),
            "s": serialize_element(credential["s"]),
        }
    }), 201


@app.route('/', methods=['GET'])
def index():
    """
    API根路径，返回可用端点
    """
    return jsonify({
        "message": "Issuer颁发者服务",
        "endpoints": {
            "GET  /pp": "获取公共参数",
            "POST /issue": "颁发凭证（支持公开/盲属性混合）",
        }
    }), 200


# ==================== Main Entry ====================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Issuer颁发者服务')
    parser.add_argument('-n', type=int, default=10, help='属性数量上限（默认: 10）')
    parser.add_argument('--port', type=int, default=5002, help='服务端口（默认: 5002）')
    args = parser.parse_args()

    print("=" * 60)
    print(f"Issuer颁发者服务启动中... 属性数量上限: {args.n}")
    print("=" * 60)

    issuer.setup(args.n)
    app.run(debug=True, host='0.0.0.0', port=args.port)
