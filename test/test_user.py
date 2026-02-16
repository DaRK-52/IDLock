"""
User 功能测试脚本（HTTP 方式）
测试场景:
  1. 端到端认证成功（申请凭证 -> 生成DID并上链 -> 向Verifier证明）
  2. 策略不匹配导致认证失败
"""

import socket
import threading
import time
import requests
from werkzeug.serving import make_server

from src.user import User
import src.issuer as issuer_service
import src.verifier as verifier_service
import src.blockchain as blockchain_service


def get_free_port() -> int:
    """获取空闲端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread(threading.Thread):
    """将 Flask app 以 WSGI server 方式启动在后台线程"""

    def __init__(self, app, host: str, port: int):
        super().__init__(daemon=True)
        self.server = make_server(host, port, app)

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


def wait_service_ready(base_url: str, timeout: float = 5.0):
    """等待服务就绪"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{base_url}/", timeout=1)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"服务未就绪: {base_url}")


def setup_services(n: int = 3):
    """启动 issuer / verifier / blockchain 三个服务，并完成 verifier 初始化"""
    # 重置并初始化 issuer
    issuer_service.issuer.setup(n)

    # 启动服务
    issuer_port = get_free_port()
    verifier_port = get_free_port()
    blockchain_port = get_free_port()

    issuer_server = ServerThread(issuer_service.app, "127.0.0.1", issuer_port)
    verifier_server = ServerThread(verifier_service.app, "127.0.0.1", verifier_port)
    blockchain_server = ServerThread(blockchain_service.app, "127.0.0.1", blockchain_port)

    issuer_server.start()
    verifier_server.start()
    blockchain_server.start()

    issuer_url = f"http://127.0.0.1:{issuer_port}"
    verifier_url = f"http://127.0.0.1:{verifier_port}"
    blockchain_url = f"http://127.0.0.1:{blockchain_port}"

    wait_service_ready(issuer_url)
    wait_service_ready(verifier_url)
    wait_service_ready(blockchain_url)

    # 用 issuer 的 PP 初始化 verifier
    pp_data = requests.get(f"{issuer_url}/pp", timeout=3).json()["pp"]
    resp = requests.post(f"{verifier_url}/setup", json={"pp": pp_data}, timeout=3)
    assert resp.status_code == 201, f"Verifier setup 失败: {resp.text}"

    return {
        "issuer_url": issuer_url,
        "verifier_url": verifier_url,
        "blockchain_url": blockchain_url,
        "issuer_server": issuer_server,
        "verifier_server": verifier_server,
        "blockchain_server": blockchain_server,
    }


def teardown_services(svc):
    svc["issuer_server"].stop()
    svc["verifier_server"].stop()
    svc["blockchain_server"].stop()


def test_user_auth_success():
    """测试1: 端到端认证成功"""
    print("\n" + "=" * 60)
    print("测试1: User 端到端认证成功")
    print("=" * 60)

    svc = setup_services(n=3)
    try:
        # 设置 verifier 访问策略
        policy = {"m1": "alice", "m3": "student"}
        r = requests.post(f"{svc['verifier_url']}/policy", json={"policy": policy}, timeout=3)
        assert r.status_code == 201, f"设置策略失败: {r.text}"

        user = User(
            rid="user-001",
            issuer_base_url=svc["issuer_url"],
            blockchain_base_url=svc["blockchain_url"],
            verifier_base_url=svc["verifier_url"],
        )

        attributes = {"m1": "alice", "m2": "22", "m3": "student"}

        # 完整认证
        verify_result = user.authenticate(attributes=attributes, disclosed_indices={1, 3})
        assert verify_result["valid"] is True, f"认证应成功: {verify_result}"

        # 将注册交易打包入块，验证链路可用
        mine_resp = requests.post(f"{svc['blockchain_url']}/block/mine", timeout=3)
        assert mine_resp.status_code == 201, f"打包区块失败: {mine_resp.text}"

        print(f"  验证结果: {verify_result}")
        print("  ✅ 端到端认证成功")
    finally:
        teardown_services(svc)


def test_user_auth_fail_policy():
    """测试2: 策略不匹配导致认证失败"""
    print("\n" + "=" * 60)
    print("测试2: 策略不匹配导致认证失败")
    print("=" * 60)

    svc = setup_services(n=3)
    try:
        # 设置不匹配策略
        policy = {"m1": "bob"}
        r = requests.post(f"{svc['verifier_url']}/policy", json={"policy": policy}, timeout=3)
        assert r.status_code == 201, f"设置策略失败: {r.text}"

        user = User(
            rid="user-002",
            issuer_base_url=svc["issuer_url"],
            blockchain_base_url=svc["blockchain_url"],
            verifier_base_url=svc["verifier_url"],
        )

        attributes = {"m1": "alice", "m2": "22", "m3": "student"}

        # 用户认证应失败（verifier 返回 400，User 会抛 RuntimeError）
        failed = False
        try:
            user.authenticate(attributes=attributes, disclosed_indices={1, 3})
        except RuntimeError as e:
            failed = True
            assert "不满足策略" in str(e) or "failed" in str(e)
            print(f"  捕获预期失败: {e}")

        assert failed, "应当认证失败"
        print("  ✅ 策略不匹配被正确拒绝")
    finally:
        teardown_services(svc)


if __name__ == '__main__':
    print("User 功能测试")
    print("=" * 60)

    test_user_auth_success()
    test_user_auth_fail_policy()

    print("\n" + "=" * 60)
    print("全部测试通过 ✅")
    print("=" * 60)
