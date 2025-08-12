import os
import math
import struct
import time
import hashlib
import mmap
from typing import List, Tuple


class SM3:
    """
    SM3密码杂凑算法实现
    GB/T 32905-2016 标准
    """
    IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

    T_j = [0x79CC4519] * 16 + [0x7A879D8A] * 48

    @staticmethod
    def _ff_j(x: int, y: int, z: int, j: int) -> int:
        """布尔函数FF_j"""
        if j < 16:
            return x ^ y ^ z
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _gg_j(x: int, y: int, z: int, j: int) -> int:
        """布尔函数GG_j"""
        if j < 16:
            return x ^ y ^ z
        return (x & y) | ((~x) & z)

    @staticmethod
    def _p0(x: int) -> int:
        """置换函数P0"""
        return x ^ ((x << 9) & 0xFFFFFFFF) ^ ((x >> 23) & 0x1FF)

    @staticmethod
    def _p1(x: int) -> int:
        """置换函数P1"""
        return x ^ ((x << 15) & 0xFFFFFFFF) ^ ((x >> 17) & 0x7FFF)

    @staticmethod
    def _cf(v: List[int], block: bytes) -> List[int]:
        """压缩函数主逻辑"""
        w = [0] * 68
        w_ = [0] * 64

        # 消息扩展
        for i in range(16):
            w[i] = struct.unpack(">I", block[i * 4:i * 4 + 4])[0]

        for j in range(16, 68):
            w[j] = SM3._p1(w[j - 16] ^ w[j - 9] ^ (SM3._rotl(w[j - 3], 15))) ^ \
                   (SM3._rotl(w[j - 13], 7)) ^ w[j - 6]

        for j in range(64):
            w_[j] = w[j] ^ w[j + 4]

        a, b, c, d, e, f, g, h = v

        # 轮函数
        for j in range(64):
            ss1 = SM3._rotl((SM3._rotl(a, 12) + e + SM3._rotl(SM3.T_j[j], j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ SM3._rotl(a, 12)
            tt1 = (SM3._ff_j(a, b, c, j) + d + ss2 + w_[j]) & 0xFFFFFFFF
            tt2 = (SM3._gg_j(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = SM3._rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = SM3._rotl(f, 19)
            f = e
            e = SM3._p0(tt2)

        return [v[0] ^ a, v[1] ^ b, v[2] ^ c, v[3] ^ d,
                v[4] ^ e, v[5] ^ f, v[6] ^ g, v[7] ^ h]

    @staticmethod
    def _rotl(x: int, n: int) -> int:
        """循环左移(修复负位移)"""
        n = n % 32  # 确保位移量在0-31范围内
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    @staticmethod
    def hash(msg: bytes) -> bytes:
        """计算SM3哈希值(修复填充计算)"""
        # 修复1：正确的填充计算方法
        length = len(msg)
        msg += b'\x80'

        # 计算需要填充的0字节数 (GB/T 32905-2016标准)
        pad_zeros = (56 - (length + 1) % 64) % 64
        if pad_zeros < 0:
            pad_zeros += 64

        msg += b'\x00' * pad_zeros
        msg += struct.pack(">Q", length * 8)

        # 分组处理
        blocks = [msg[i:i + 64] for i in range(0, len(msg), 64)]
        v = SM3.IV.copy()

        for block in blocks:
            v = SM3._cf(v, block)

        return b''.join(struct.pack(">I", x) for x in v)


class OptimizedSM3(SM3):
    """优化版SM3实现"""

    @staticmethod
    def hash(msg: bytes) -> bytes:
        # 优化1: 合并填充和长度计算
        length = len(msg)
        # 确保填充后长度是64的倍数
        pad_zeros = (56 - (length + 1) % 64) % 64
        if pad_zeros < 0:
            pad_zeros += 64
        padded = msg + b'\x80' + (b'\x00' * pad_zeros) + struct.pack(">Q", length * 8)
        # 优化2: 直接内存访问减少复制
        # 添加缓冲区长度校验
        total_bytes = len(padded)
        if total_bytes % 64 != 0:
            # 确保填充正确
            additional = 64 - (total_bytes % 64)
            padded += b'\x00' * additional
            total_bytes = len(padded)

        blocks = memoryview(padded).cast("B", shape=(total_bytes // 64, 64))

        # 优化3: 使用本地变量代替列表
        a, b, c, d, e, f, g, h = SM3.IV

        # 优化4: 循环展开(4:1)
        for i in range(0, len(blocks), 4):
            # 预取未来4块
            block0 = blocks[i].tobytes()
            block1 = blocks[i + 1].tobytes() if i + 1 < len(blocks) else None
            block2 = blocks[i + 2].tobytes() if i + 2 < len(blocks) else None
            block3 = blocks[i + 3].tobytes() if i + 3 < len(blocks) else None

            # 并行处理多个块
            a, b, c, d, e, f, g, h = OptimizedSM3._cf4(
                a, b, c, d, e, f, g, h,
                block0, block1, block2, block3
            )

        return b''.join(struct.pack(">I", x) for x in [a, b, c, d, e, f, g, h])

    @staticmethod
    def _cf4(a, b, c, d, e, f, g, h,
             block0: bytes, block1: bytes, block2: bytes, block3: bytes) -> Tuple[int]:
        """并行处理4个块的压缩函数"""
        results = []
        for block in [block0, block1, block2, block3]:
            if block is None:
                continue
            v = SM3._cf([a, b, c, d, e, f, g, h], block)
            results.append(v)

        # 合并结果 (流水线优化)
        avg = [0] * 8
        for res in results:
            for j in range(8):
                avg[j] = (avg[j] + res[j]) % (1 << 32)
        return tuple(avg)


class MerkleTree:
    """基于SM3的Merkle树实现 (RFC 6962标准)"""

    def __init__(self, data: List[bytes]):
        self.leaves = [OptimizedSM3.hash(d) for d in data]
        self.tree = self._build_tree(self.leaves)

    def _build_tree(self, nodes: List[bytes]) -> List[List[bytes]]:
        """构建Merkle树"""
        tree = [nodes]
        while len(nodes) > 1:
            new_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                new_node = OptimizedSM3.hash(left + right)
                new_level.append(new_node)
            tree.append(new_level)
            nodes = new_level
        return tree

    def root(self) -> bytes:
        """获取树根哈希值"""
        return self.tree[-1][0]

    def proof(self, index: int) -> List[bytes]:
        """生成存在性证明"""
        proof_path = []
        current_index = index

        for level in self.tree[:-1]:
            if current_index % 2 == 0:
                if current_index + 1 < len(level):
                    sibling = level[current_index + 1]
                else:
                    sibling = level[current_index]
            else:
                sibling = level[current_index - 1]

            proof_path.append(sibling)
            current_index //= 2

        return proof_path

    def verify_proof(self, index: int, leaf: bytes, proof: List[bytes]) -> bool:
        """验证存在性证明"""
        current_hash = leaf

        for sibling in proof:
            if index % 2 == 0:
                current_hash = OptimizedSM3.hash(current_hash + sibling)
            else:
                current_hash = OptimizedSM3.hash(sibling + current_hash)
            index //= 2

        return current_hash == self.root()

    def non_inclusion_proof(self, leaf: bytes) -> Tuple[List[bytes], bytes]:
        """生成不存在性证明"""
        # 查找最近叶节点
        best_match = None
        best_index = None
        min_diff = float('inf')

        for i, l in enumerate(self.leaves):
            diff = self._hash_diff(leaf, l)
            if diff < min_diff:
                min_diff = diff
                best_match = l
                best_index = i

        # 生成该叶节点的存在性证明
        proof = self.proof(best_index)
        return proof, best_match

    def _hash_diff(self, a: bytes, b: bytes) -> int:
        """计算哈希值的差异值"""
        diff = 0
        for byte_a, byte_b in zip(a, b):
            diff |= byte_a ^ byte_b
            if diff:
                break
        return diff


def test_sm3_optimization():
    """SM3性能优化测试"""
    data = os.urandom(10 * 1024 * 1024)  # 10MB随机数据

    # 原始实现性能
    start = time.time()
    SM3.hash(data)
    basic_time = time.time() - start

    # 优化实现性能
    start = time.time()
    OptimizedSM3.hash(data)
    optimized_time = time.time() - start

    print(f"SM3性能优化测试:")
    print(f"原始实现: {basic_time:.4f}秒")
    print(f"优化实现: {optimized_time:.4f}秒")
    print(f"加速比: {basic_time / optimized_time:.2f}x")


def length_extension_attack():
    """长度扩展攻击演示"""
    # 原始消息和密钥
    secret = b"supersecret"
    original_msg = b"data"
    mac = OptimizedSM3.hash(secret + original_msg)

    # 攻击: 不知道密钥的情况下扩展附加数据
    append_msg = b"malicious"

    # 计算新消息的哈希值
    # 1. 构造填充后的消息
    total_len = len(secret) + len(original_msg)
    pad_len = (55 - total_len) % 64 + 1
    padding = b'\x80' + (b'\x00' * pad_len) + struct.pack(">Q", total_len * 8)

    # 2. 新消息结构: (unknown secret) + original + padding + append
    forged_msg = original_msg + padding + append_msg

    # 3. 使用MAC作为中间状态继续计算
    state = struct.unpack(">8I", mac)
    new_mac = OptimizedSM3._cf(list(state), append_msg + b'\x80' + b'\x00' * 55 + struct.pack(">Q", (len(forged_msg) + len(secret)) * 8))

    # 4. 验证攻击是否成功
    actual_mac = OptimizedSM3.hash(secret + forged_msg)
    print("\n长度扩展攻击结果:")
    print(f"预测哈希: {new_mac.hex()}")
    print(f"实际哈希: {actual_mac.hex()}")
    print(f"攻击成功: {new_mac == actual_mac}")


def generate_large_data(n: int) -> List[bytes]:
    """生成大规模测试数据"""
    return [os.urandom(100) for _ in range(n)]


def test_merkle_tree():
    """Merkle树功能测试"""
    data = generate_large_data(100000)  # 10万叶子节点

    # 构建Merkle树
    start = time.time()
    tree = MerkleTree(data)
    build_time = time.time() - start
    print(f"\n构建10万节点Merkle树耗时: {build_time:.2f}秒")

    # 存在性证明
    start = time.time()
    proof = tree.proof(12345)
    verify_result = tree.verify_proof(12345, data[12345], proof)
    print(f"存在性证明验证: {verify_result} (耗时: {time.time() - start:.4f}秒)")

    # 不存在性证明
    new_data = os.urandom(100)
    start = time.time()
    proof, closest = tree.non_inclusion_proof(new_data)
    print(f"非存在证明: 最接近的节点 {closest[:8].hex()}... (耗时: {time.time() - start:.4f}秒)")


if __name__ == "__main__":
    # 测试基础功能
    test_msg = b"Hello, SM3!"
    print(f"SM3测试哈希: {OptimizedSM3.hash(test_msg).hex()}")

    # 性能优化测试
    test_sm3_optimization()

    # 长度扩展攻击
    length_extension_attack()

    # Merkle树测试
    test_merkle_tree()