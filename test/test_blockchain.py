"""
Blockchain 功能测试脚本
测试场景:
  1. 创世区块自动生成
  2. 交易提交到缓冲区
  3. 区块打包（含缓冲区清空）
  4. SPV 证明生成与验证
  5. 区块链完整性（前序哈希链接）
  6. 边界情况（空缓冲区打包、无效高度查询、不存在的交易）
"""

from src.blockchain import Blockchain, MerkleTree, Block


def test_genesis_block():
    """测试1: 创世区块自动生成"""
    print("\n" + "=" * 60)
    print("测试1: 创世区块自动生成")
    print("=" * 60)

    bc = Blockchain()

    assert len(bc.chain) == 1, "链应包含1个创世区块"
    genesis = bc.chain[0]
    assert genesis.height == 0, "创世区块高度应为0"
    assert genesis.prev_hash == "0" * 64, "创世区块的前序哈希应为全0"
    assert len(genesis.transactions) == 1, "创世区块应包含1笔交易"
    assert genesis.transactions[0] == {"u": "genesis", "v": "genesis"}, "创世交易内容不匹配"

    print(f"  区块高度: {genesis.height}")
    print(f"  区块哈希: {genesis.hash()}")
    print(f"  Merkle根: {genesis.merkle_root}")
    print("  ✅ 创世区块验证通过")


def test_add_transaction():
    """测试2: 交易提交到缓冲区"""
    print("\n" + "=" * 60)
    print("测试2: 交易提交到缓冲区")
    print("=" * 60)

    bc = Blockchain()

    result1 = bc.add_transaction("Alice", "Bob")
    assert result1["pending_count"] == 1
    assert result1["transaction"] == {"u": "Alice", "v": "Bob"}

    result2 = bc.add_transaction("Bob", "Charlie")
    assert result2["pending_count"] == 2

    result3 = bc.add_transaction("Charlie", "Alice")
    assert result3["pending_count"] == 3

    assert len(bc.pending_transactions) == 3, "缓冲区应有3笔交易"

    print(f"  提交3笔交易，缓冲区大小: {len(bc.pending_transactions)}")
    print("  ✅ 交易提交验证通过")


def test_mine_block():
    """测试3: 区块打包与缓冲区清空"""
    print("\n" + "=" * 60)
    print("测试3: 区块打包与缓冲区清空")
    print("=" * 60)

    bc = Blockchain()

    bc.add_transaction("Alice", "Bob")
    bc.add_transaction("Bob", "Charlie")
    bc.add_transaction("Charlie", "Alice")

    result = bc.mine_block()
    assert result["message"] == "区块生成成功"
    assert result["transactions_count"] == 3
    assert len(bc.chain) == 2, "链应包含2个区块"
    assert len(bc.pending_transactions) == 0, "缓冲区应已清空"

    new_block = bc.chain[1]
    assert new_block.height == 1, "新区块高度应为1"
    assert len(new_block.transactions) == 3, "新区块应包含3笔交易"

    print(f"  新区块高度: {new_block.height}")
    print(f"  新区块哈希: {new_block.hash()}")
    print(f"  包含交易数: {len(new_block.transactions)}")
    print(f"  缓冲区剩余: {len(bc.pending_transactions)}")
    print("  ✅ 区块打包验证通过")


def test_mine_empty_buffer():
    """测试4: 空缓冲区打包（应失败）"""
    print("\n" + "=" * 60)
    print("测试4: 空缓冲区打包")
    print("=" * 60)

    bc = Blockchain()

    result = bc.mine_block()
    assert "无法" in result["message"], "空缓冲区应无法生成区块"
    assert len(bc.chain) == 1, "链长度不应变化"

    print(f"  返回信息: {result['message']}")
    print("  ✅ 空缓冲区正确拒绝")


def test_chain_integrity():
    """测试5: 区块链完整性（前序哈希链接）"""
    print("\n" + "=" * 60)
    print("测试5: 区块链完整性")
    print("=" * 60)

    bc = Blockchain()

    # 生成3个区块
    for batch in range(3):
        for j in range(2):
            bc.add_transaction(f"user{batch * 2 + j}", f"user{batch * 2 + j + 1}")
        bc.mine_block()

    assert len(bc.chain) == 4, "链应包含4个区块（1创世+3新块）"

    # 验证链接关系
    for i in range(1, len(bc.chain)):
        expected_prev_hash = bc.chain[i - 1].hash()
        actual_prev_hash = bc.chain[i].prev_hash
        assert expected_prev_hash == actual_prev_hash, f"区块{i}的前序哈希不匹配"
        print(f"  区块{i}: prev_hash 正确链接到区块{i - 1}")

    print("  ✅ 区块链完整性验证通过")


def test_spv_proof():
    """测试6: SPV 证明生成与验证"""
    print("\n" + "=" * 60)
    print("测试6: SPV 证明生成与验证")
    print("=" * 60)

    bc = Blockchain()

    bc.add_transaction("Alice", "Bob")
    bc.add_transaction("Bob", "Charlie")
    bc.add_transaction("Charlie", "David")
    bc.add_transaction("David", "Eve")
    bc.mine_block()

    # 验证存在的交易
    proof = bc.get_spv_proof(1, "Bob", "Charlie")
    assert proof is not None, "交易应存在"
    assert proof["transaction"] == {"u": "Bob", "v": "Charlie"}
    assert proof["block_height"] == 1
    assert proof["tx_index"] == 1

    print(f"  交易: Bob → Charlie")
    print(f"  区块高度: {proof['block_height']}")
    print(f"  交易索引: {proof['tx_index']}")
    print(f"  Merkle根: {proof['merkle_root']}")
    print(f"  证明路径长度: {len(proof['merkle_proof'])}")

    # 使用 MerkleTree 验证证明
    block = bc.chain[1]
    tx = {"u": "Bob", "v": "Charlie"}
    valid = MerkleTree.verify_proof(tx, block.merkle_root, proof["merkle_proof"])
    assert valid, "SPV 证明验证失败!"
    print("  ✅ SPV 证明验证通过")


def test_spv_all_transactions():
    """测试7: 验证区块中所有交易的 SPV 证明"""
    print("\n" + "=" * 60)
    print("测试7: 区块内所有交易的 SPV 证明")
    print("=" * 60)

    bc = Blockchain()

    txs = [("A", "B"), ("C", "D"), ("E", "F"), ("G", "H"), ("I", "J")]
    for u, v in txs:
        bc.add_transaction(u, v)
    bc.mine_block()

    block = bc.chain[1]
    for idx, (u, v) in enumerate(txs):
        proof = bc.get_spv_proof(1, u, v)
        assert proof is not None, f"交易 {u}→{v} 应存在"
        assert proof["tx_index"] == idx

        valid = MerkleTree.verify_proof({"u": u, "v": v}, block.merkle_root, proof["merkle_proof"])
        assert valid, f"交易 {u}→{v} 的 SPV 证明验证失败!"
        print(f"  交易 {u}→{v} (索引{idx}): ✅")

    print("  ✅ 所有交易的 SPV 证明验证通过")


def test_spv_nonexistent():
    """测试8: 不存在交易的 SPV 查询"""
    print("\n" + "=" * 60)
    print("测试8: 不存在交易的 SPV 查询")
    print("=" * 60)

    bc = Blockchain()

    bc.add_transaction("Alice", "Bob")
    bc.mine_block()

    # 交易不存在
    proof = bc.get_spv_proof(1, "Alice", "Charlie")
    assert proof is None, "不存在的交易应返回 None"
    print("  查询不存在的交易: 返回 None ✅")

    # 无效区块高度
    proof = bc.get_spv_proof(99, "Alice", "Bob")
    assert proof is None, "无效高度应返回 None"
    print("  查询无效区块高度: 返回 None ✅")

    # 负数高度
    proof = bc.get_spv_proof(-1, "Alice", "Bob")
    assert proof is None, "负数高度应返回 None"
    print("  查询负数区块高度: 返回 None ✅")

    print("  ✅ 边界情况验证通过")


def test_multiple_blocks():
    """测试9: 多区块连续打包"""
    print("\n" + "=" * 60)
    print("测试9: 多区块连续打包与跨区块查询")
    print("=" * 60)

    bc = Blockchain()

    # 区块1
    bc.add_transaction("Alice", "Bob")
    bc.mine_block()

    # 区块2
    bc.add_transaction("Charlie", "David")
    bc.add_transaction("Eve", "Frank")
    bc.mine_block()

    # 区块3
    bc.add_transaction("Grace", "Heidi")
    bc.mine_block()

    assert len(bc.chain) == 4

    # 验证各区块中的交易
    proof1 = bc.get_spv_proof(1, "Alice", "Bob")
    assert proof1 is not None and proof1["block_height"] == 1
    print(f"  区块1: Alice→Bob ✅")

    proof2 = bc.get_spv_proof(2, "Eve", "Frank")
    assert proof2 is not None and proof2["block_height"] == 2
    print(f"  区块2: Eve→Frank ✅")

    proof3 = bc.get_spv_proof(3, "Grace", "Heidi")
    assert proof3 is not None and proof3["block_height"] == 3
    print(f"  区块3: Grace→Heidi ✅")

    # 跨区块查询应失败
    cross = bc.get_spv_proof(1, "Charlie", "David")
    assert cross is None, "跨区块查询应返回 None"
    print(f"  跨区块查询 Charlie→David 在区块1: None ✅")

    print("  ✅ 多区块验证通过")


def test_merkle_single_transaction():
    """测试10: 单笔交易的 Merkle 树"""
    print("\n" + "=" * 60)
    print("测试10: 单笔交易的 Merkle 树")
    print("=" * 60)

    bc = Blockchain()
    bc.add_transaction("Solo", "Tx")
    bc.mine_block()

    block = bc.chain[1]
    assert len(block.transactions) == 1

    proof = bc.get_spv_proof(1, "Solo", "Tx")
    assert proof is not None
    # 单笔交易时，Merkle 根就是交易哈希本身
    tx_hash = MerkleTree.hash_transaction({"u": "Solo", "v": "Tx"})
    assert block.merkle_root == tx_hash, "单笔交易的 Merkle 根应等于交易哈希"
    assert len(proof["merkle_proof"]) == 0, "单笔交易的证明路径应为空"

    print(f"  Merkle根: {block.merkle_root}")
    print(f"  交易哈希: {tx_hash}")
    print(f"  证明路径长度: {len(proof['merkle_proof'])}")
    print("  ✅ 单笔交易 Merkle 树验证通过")


if __name__ == '__main__':
    print("Blockchain 功能测试")
    print("=" * 60)

    test_genesis_block()
    test_add_transaction()
    test_mine_block()
    test_mine_empty_buffer()
    test_chain_integrity()
    test_spv_proof()
    test_spv_all_transactions()
    test_spv_nonexistent()
    test_multiple_blocks()
    test_merkle_single_transaction()

    print("\n" + "=" * 60)
    print("全部测试通过 ✅")
    print("=" * 60)
