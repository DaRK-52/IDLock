import requests
from typing import Dict, Set, Optional
from charm.toolbox.pairinggroup import PairingGroup, G1, ZR

from src.issuer import deserialize_pp, serialize_element, deserialize_element

# 与 issuer / verifier 保持同一群参数
group = PairingGroup('MNT224')


class User:
    """用户客户端：通过 HTTP 调用 Issuer / Blockchain / Verifier 完成身份认证流程"""

    def __init__(
        self,
        rid: str,
        issuer_base_url: str,
        blockchain_base_url: str,
        verifier_base_url: str,
        timeout: int = 10,
    ):
        self.rid = rid
        self.issuer_base_url = issuer_base_url.rstrip('/')
        self.blockchain_base_url = blockchain_base_url.rstrip('/')
        self.verifier_base_url = verifier_base_url.rstrip('/')
        self.timeout = timeout

        self.PP: Optional[Dict] = None
        self.attributes: Optional[Dict[str, str]] = None
        self.credential: Optional[Dict] = None   # {A, x, s} (group elements)
        self.did: Optional[Dict] = None          # {u, v} (group elements), 按用户语义保存 u = v^s

    # ==================== HTTP Helpers ====================

    def _post_json(self, url: str, payload: Dict) -> Dict:
        resp = requests.post(url, json=payload, timeout=self.timeout)
        if resp.status_code >= 400:
            raise RuntimeError(f"POST {url} failed: {resp.status_code} {resp.text}")
        return resp.json()

    def _get_json(self, url: str) -> Dict:
        resp = requests.get(url, timeout=self.timeout)
        if resp.status_code >= 400:
            raise RuntimeError(f"GET {url} failed: {resp.status_code} {resp.text}")
        return resp.json()

    # ==================== Step 1: 申请凭证 ====================

    def fetch_public_params(self) -> Dict:
        """从 Issuer 获取公共参数并反序列化"""
        data = self._get_json(f"{self.issuer_base_url}/pp")
        self.PP = deserialize_pp(data["pp"])
        return self.PP

    def request_credential(self, attributes: Dict[str, str]) -> Dict:
        """
        输入属性向 Issuer 申请凭证

        Args:
            attributes: {"m1": "...", "m2": "...", ...}
        Returns:
            credential: {"A": G1, "x": ZR, "s": ZR}
        """
        if self.PP is None:
            self.fetch_public_params()

        payload_attrs = {k: {"value": v} for k, v in attributes.items()}
        data = self._post_json(
            f"{self.issuer_base_url}/issue",
            {"attributes": payload_attrs},
        )

        raw = data["credential"]
        self.credential = {
            "A": deserialize_element(raw["A"]),
            "x": deserialize_element(raw["x"]),
            "s": deserialize_element(raw["s"]),
        }
        self.attributes = attributes
        return self.credential

    # ==================== Step 2: 生成 DID 并上链 ====================

    def generate_did(self) -> Dict:
        """
        使用凭证中的 s 生成 DID = (u, v)
        按用户语义保存: u = v^s

        注意：当前 verifier 校验形式为 did_v = did_u^s。
        因此在提交 verifier 证明时将做映射: did_u_for_verifier = v, did_v_for_verifier = u。
        """
        if self.credential is None:
            raise RuntimeError("请先申请凭证")

        s = self.credential["s"]
        v = group.random(G1)
        u = v ** s  # 按需求: u = v^s

        self.did = {"u": u, "v": v}
        return self.did

    def register_did_on_blockchain(self) -> Dict:
        """将 DID 注册为区块链交易"""
        if self.did is None:
            self.generate_did()

        # blockchain 的交易字段是字符串，这里序列化群元素
        payload = {
            "u": serialize_element(self.did["u"]),
            "v": serialize_element(self.did["v"]),
        }

        return self._post_json(f"{self.blockchain_base_url}/transaction/new", payload)

    # ==================== Step 3: 向 Verifier 证明身份 ====================

    def build_identity_proof(self, disclosed_indices: Set[int]) -> Dict:
        """
        生成提交给 verifier 的证明（与 src.verifier.verify 兼容）

        Args:
            disclosed_indices: 公开属性索引集合，如 {1, 3}
        Returns:
            proof payload (已序列化，可直接 HTTP 发送)
        """
        if self.PP is None:
            self.fetch_public_params()
        if self.credential is None or self.attributes is None:
            raise RuntimeError("请先完成凭证申请")
        if self.did is None:
            self.generate_did()

        PP = self.PP
        A = self.credential["A"]
        x = self.credential["x"]
        s = self.credential["s"]
        n = PP["n"]

        # 按 verifier 约定映射 DID（verifier 校验 did_v = did_u^s）
        did_u_for_verifier = self.did["v"]
        did_v_for_verifier = self.did["u"]

        # 属性映射到 ZR
        messages = {}
        for i in range(1, n + 1):
            key = f"m{i}"
            if key not in self.attributes:
                raise RuntimeError(f"缺少属性 {key}")
            messages[i] = PP["H"](self.attributes[key], ZR)

        hidden_indices = set(range(1, n + 1)) - disclosed_indices

        # 随机化凭证
        r1 = group.random(ZR)
        A_prime = A ** r1

        B = PP["g1"] * (PP["h0"] ** s)
        for i in range(1, n + 1):
            B = B * (PP[f"h{i}"] ** messages[i])

        A_bar = (A_prime ** (-x)) * (B ** r1)

        s_prime = s * r1
        m_primes = {i: messages[i] * r1 for i in hidden_indices}

        # Schnorr 承诺随机数
        k_x = group.random(ZR)
        k_r1 = group.random(ZR)
        k_s_prime = group.random(ZR)
        k_s = group.random(ZR)
        k_m_primes = {i: group.random(ZR) for i in hidden_indices}

        # B_D = g1 * Π_{j∈D} h_j^m_j
        B_D = PP["g1"]
        for j in disclosed_indices:
            B_D = B_D * (PP[f"h{j}"] ** messages[j])

        T = (A_prime ** (-k_x)) * (B_D ** k_r1) * (PP["h0"] ** k_s_prime)
        for i in hidden_indices:
            T = T * (PP[f"h{i}"] ** k_m_primes[i])

        # DID 关联证明
        R3 = did_u_for_verifier ** k_s

        # challenge
        challenge_input = (
            serialize_element(A_prime)
            + serialize_element(A_bar)
            + serialize_element(T)
            + serialize_element(R3)
        )
        c = group.hash(challenge_input, ZR)

        # responses
        z_x = k_x + c * x
        z_r1 = k_r1 + c * r1
        z_s_prime = k_s_prime + c * s_prime
        z_s = k_s + c * s

        z_hidden = {}
        for i in hidden_indices:
            z_hidden[f"m{i}"] = k_m_primes[i] + c * m_primes[i]

        disclosed_attrs = {f"m{j}": self.attributes[f"m{j}"] for j in disclosed_indices}

        return {
            "disclosed_attrs": disclosed_attrs,
            "did_u": serialize_element(did_u_for_verifier),
            "did_v": serialize_element(did_v_for_verifier),
            "A_prime": serialize_element(A_prime),
            "A_bar": serialize_element(A_bar),
            "c": serialize_element(c),
            "z_x": serialize_element(z_x),
            "z_r1": serialize_element(z_r1),
            "z_s_prime": serialize_element(z_s_prime),
            "z_s": serialize_element(z_s),
            "R3": serialize_element(R3),
            "z_hidden": {k: serialize_element(v) for k, v in z_hidden.items()},
        }

    def verify_identity(self, disclosed_indices: Set[int]) -> Dict:
        """构建证明并提交 verifier 验证"""
        proof_payload = self.build_identity_proof(disclosed_indices)
        return self._post_json(f"{self.verifier_base_url}/verify", proof_payload)

    # ==================== Orchestration ====================

    def authenticate(self, attributes: Dict[str, str], disclosed_indices: Set[int]) -> Dict:
        """
        完整认证流程：申请凭证 -> 生成DID -> 上链 -> 向 verifier 证明
        """
        self.request_credential(attributes)
        self.generate_did()
        self.register_did_on_blockchain()
        return self.verify_identity(disclosed_indices)
