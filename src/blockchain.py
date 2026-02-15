from flask import Flask, jsonify, request
import hashlib
import json
import time
from typing import List, Dict, Optional, Tuple

app = Flask(__name__)


# ==================== Merkle Tree Implementation ====================

class MerkleTree:
    """实现Merkle树用于SPV验证"""
    
    @staticmethod
    def hash_transaction(tx: Dict) -> str:
        """计算交易的哈希值"""
        tx_string = json.dumps(tx, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        """计算两个哈希值的组合哈希"""
        return hashlib.sha256((left + right).encode()).hexdigest()
    
    @classmethod
    def build_merkle_root(cls, transactions: List[Dict]) -> str:
        """构建Merkle树并返回根哈希"""
        if not transactions:
            return hashlib.sha256(b"").hexdigest()
        
        # 计算所有交易的哈希作为叶子节点
        current_level = [cls.hash_transaction(tx) for tx in transactions]
        
        # 自底向上构建Merkle树
        while len(current_level) > 1:
            next_level = []
            
            # 两两配对计算父节点哈希
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # 如果是奇数个节点，复制最后一个
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(cls.hash_pair(left, right))
            
            current_level = next_level
        
        return current_level[0]
    
    @classmethod
    def get_merkle_proof(cls, transactions: List[Dict], tx_index: int) -> List[Dict]:
        """
        获取指定交易的Merkle证明路径
        返回: [{"hash": str, "position": "left"/"right"}]
        """
        if tx_index < 0 or tx_index >= len(transactions):
            return []
        
        # 计算所有交易的哈希作为叶子节点
        current_level = [cls.hash_transaction(tx) for tx in transactions]
        proof = []
        current_index = tx_index
        
        # 自底向上构建证明路径
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                
                # 如果当前索引在这对节点中，记录兄弟节点
                if i == current_index:
                    proof.append({"hash": right, "position": "right"})
                    current_index = i // 2
                elif i + 1 == current_index:
                    proof.append({"hash": left, "position": "left"})
                    current_index = i // 2
                
                next_level.append(cls.hash_pair(left, right))
            
            current_level = next_level
        
        return proof
    
    @classmethod
    def verify_proof(cls, tx: Dict, merkle_root: str, proof: List[Dict]) -> bool:
        """验证Merkle证明是否有效"""
        current_hash = cls.hash_transaction(tx)
        
        for proof_element in proof:
            sibling_hash = proof_element["hash"]
            position = proof_element["position"]
            
            if position == "left":
                current_hash = cls.hash_pair(sibling_hash, current_hash)
            else:
                current_hash = cls.hash_pair(current_hash, sibling_hash)
        
        return current_hash == merkle_root


# ==================== Blockchain Implementation ====================

class Block:
    """区块类"""
    
    def __init__(self, height: int, prev_hash: str, transactions: List[Dict], timestamp: float = None):
        self.height = height
        self.prev_hash = prev_hash
        self.transactions = transactions
        self.timestamp = timestamp or time.time()
        self.merkle_root = MerkleTree.build_merkle_root(transactions)
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "header": {
                "height": self.height,
                "prev_hash": self.prev_hash,
                "merkle_root": self.merkle_root,
                "timestamp": self.timestamp
            },
            "transactions": self.transactions
        }
    
    def hash(self) -> str:
        """计算区块哈希"""
        header_string = json.dumps(self.to_dict()["header"], sort_keys=True)
        return hashlib.sha256(header_string.encode()).hexdigest()


class Blockchain:
    """区块链类"""
    
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """创建创世区块"""
        genesis_tx = {"u": "genesis", "v": "genesis"}
        genesis_block = Block(
            height=0,
            prev_hash="0" * 64,  # 64个0表示没有前序区块
            transactions=[genesis_tx],
            timestamp=time.time()
        )
        self.chain.append(genesis_block)
        print(f"创世区块已创建，哈希: {genesis_block.hash()}")
    
    def add_transaction(self, u: str, v: str) -> Dict:
        """添加交易到缓冲区"""
        transaction = {"u": u, "v": v}
        self.pending_transactions.append(transaction)
        return {
            "message": "交易已添加到缓冲区",
            "transaction": transaction,
            "pending_count": len(self.pending_transactions)
        }
    
    def mine_block(self) -> Dict:
        """
        打包区块：将缓冲区中的所有交易打包成新区块
        """
        if not self.pending_transactions:
            return {"message": "缓冲区为空，无法生成区块"}
        
        # 获取最后一个区块
        last_block = self.chain[-1]
        
        # 创建新区块
        new_block = Block(
            height=last_block.height + 1,
            prev_hash=last_block.hash(),
            transactions=self.pending_transactions.copy()
        )
        
        # 添加到链中
        self.chain.append(new_block)
        
        # 清空缓冲区
        tx_count = len(self.pending_transactions)
        self.pending_transactions.clear()
        
        return {
            "message": "区块生成成功",
            "block": new_block.to_dict(),
            "block_hash": new_block.hash(),
            "transactions_count": tx_count
        }
    
    def get_spv_proof(self, block_height: int, u: str, v: str) -> Optional[Dict]:
        """
        获取交易的SPV证明
        返回: SPV证明或None（如果交易不存在）
        """
        # 检查区块高度是否有效
        if block_height < 0 or block_height >= len(self.chain):
            return None
        
        block = self.chain[block_height]
        transaction = {"u": u, "v": v}
        
        # 查找交易在区块中的索引
        tx_index = None
        for i, tx in enumerate(block.transactions):
            if tx["u"] == u and tx["v"] == v:
                tx_index = i
                break
        
        # 如果交易不存在，返回None
        if tx_index is None:
            return None
        
        # 生成Merkle证明
        merkle_proof = MerkleTree.get_merkle_proof(block.transactions, tx_index)
        
        return {
            "transaction": transaction,
            "block_height": block_height,
            "merkle_root": block.merkle_root,
            "merkle_proof": merkle_proof,
            "tx_index": tx_index,
            "timestamp": block.timestamp
        }
    
    def get_chain(self) -> List[Dict]:
        """获取完整的区块链"""
        return [block.to_dict() for block in self.chain]
    
    def get_chain_info(self) -> Dict:
        """获取区块链信息"""
        return {
            "chain_length": len(self.chain),
            "pending_transactions": len(self.pending_transactions),
            "latest_block_hash": self.chain[-1].hash() if self.chain else None
        }


# ==================== Flask API Routes ====================

# 创建区块链实例
blockchain = Blockchain()


@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    """
    接收新交易
    POST数据格式: {"u": str, "v": str}
    """
    data = request.get_json()
    
    # 验证输入
    if not data or 'u' not in data or 'v' not in data:
        return jsonify({
            "error": "无效的输入格式，需要包含 'u' 和 'v' 字段"
        }), 400
    
    u = str(data['u'])
    v = str(data['v'])
    
    result = blockchain.add_transaction(u, v)
    return jsonify(result), 201


@app.route('/block/mine', methods=['POST'])
def mine_block():
    """
    触发区块生产
    将缓冲区中的所有交易打包成新区块
    """
    result = blockchain.mine_block()
    
    if "error" in result or "无法" in result.get("message", ""):
        return jsonify(result), 400
    
    return jsonify(result), 201


@app.route('/transaction/verify', methods=['GET'])
def verify_transaction():
    """
    查询交易的SPV证明
    参数: block_height (int), u (str), v (str)
    """
    try:
        block_height = int(request.args.get('block_height'))
        u = str(request.args.get('u'))
        v = str(request.args.get('v'))
    except (TypeError, ValueError):
        return jsonify({
            "error": "参数错误，需要提供 block_height (int), u (str), v (str)"
        }), 400
    
    proof = blockchain.get_spv_proof(block_height, u, v)
    
    if proof is None:
        return jsonify({
            "message": "交易不存在",
            "exists": False
        }), 404
    
    return jsonify({
        "message": "交易存在",
        "exists": True,
        "spv_proof": proof
    }), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    """
    获取完整区块链（用于调试和查看）
    """
    return jsonify({
        "chain": blockchain.get_chain(),
        "info": blockchain.get_chain_info()
    }), 200


@app.route('/info', methods=['GET'])
def get_info():
    """
    获取区块链基本信息
    """
    return jsonify(blockchain.get_chain_info()), 200


@app.route('/', methods=['GET'])
def index():
    """
    API根路径，返回可用端点
    """
    return jsonify({
        "message": "区块链API服务",
        "endpoints": {
            "POST /transaction/new": "提交新交易 {u: str, v: str}",
            "POST /block/mine": "生产新区块",
            "GET /transaction/verify": "验证交易 ?block_height=&u=&v=",
            "GET /chain": "查看完整区块链",
            "GET /info": "查看区块链信息"
        }
    }), 200


# ==================== Main Entry ====================

if __name__ == '__main__':
    print("=" * 60)
    print("区块链服务启动中...")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5001)
