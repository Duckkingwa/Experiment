from ecdsa import NIST256p, SigningKey
from phe import paillier
import hashlib
import random

# 1. 定义协议参数
curve = NIST256p
G = curve.generator
order = curve.order


# 2. 哈希函数 H: U → G (使用try-and-increment方法)
def H(s):
    for nonce in range(100):
        data = f"{s}_{nonce}".encode()
        h = int.from_bytes(hashlib.sha256(data).digest(), 'big') % order
        try:
            return h * G
        except:
            continue
    raise ValueError("Hash to curve failed")


# 3. 协议实现类
class DDHPrivateIntersectionSum:
    def __init__(self):
        self.pk = None
        self.sk = None
        self.k1 = random.randint(1, order - 1)

    # P1端功能实现
    def party1_step(self, V):
        # 生成加密密钥对 (P2负责)
        self.pk, self.sk = paillier.generate_paillier_keypair()

        # Round 1: 计算并发送 {H(v_i)^k1}
        self.V = V
        hashed_exponents = [H(v) * self.k1 for v in V]
        random.shuffle(hashed_exponents)
        return self.pk, hashed_exponents

    # P2端功能实现
    def party2_step(self, pk, received_from_p1, W):
        self.pk = pk
        self.W = W

        # Round 2: 计算并发送两部分数据
        # 1. {H(v_i)^{k1*k2}}
        double_exponents = [point * self.k2 for point in received_from_p1]
        random.shuffle(double_exponents)

        # 2. {(H(w_j)^k2, Enc(t_j))}
        encrypted_tuples = []
        for w, t in W:
            hw = H(w)
            encrypted_t = self.pk.encrypt(t)
            encrypted_tuples.append((hw * self.k2, encrypted_t))
        random.shuffle(encrypted_tuples)

        return double_exponents, encrypted_tuples

    # P1完成计算并返回加密求和结果
    def party1_finalize(self, double_exponents, encrypted_tuples):
        # 提取Z值 {H(v_i)^{k1k2}}
        Z = set(double_exponents)

        # 计算交集并累加加密值
        sum_ciphertext = self.pk.encrypt(0)
        count = 0

        for hw_k2, enc_t in encrypted_tuples:
            # 计算 H(w_j)^{k1*k2}
            hw_k1k2 = hw_k2 * self.k1
            if hw_k1k2 in Z:
                sum_ciphertext += enc_t
                count += 1

        # 重新随机化并返回加密结果
        randomized_sum = sum_ciphertext + self.pk.encrypt(0)
        return count, randomized_sum

    # P2解密求和结果
    def party2_decrypt(self, encrypted_sum):
        return self.sk.decrypt(encrypted_sum)


# 4. 协议执行演示
if __name__ == "__main__":
    # 模拟数据集
    V = ["user1", "user2", "user3", "user5"]
    W = [("user1", 10), ("user2", 20), ("user4", 30)]

    # 初始化协议实例
    protocol = DDHPrivateIntersectionSum()

    # P1发送第一轮数据
    pk, p1_round1 = protocol.party1_step(V)

    # P2处理并返回第二轮数据
    p2_round2_data1, p2_round2_data2 = protocol.party2_step(pk, p1_round1, W)

    # P1计算交集和加密和
    intersection_count, encrypted_sum = protocol.party1_finalize(
        p2_round2_data1, p2_round2_data2
    )

    # P2解密最终结果
    intersection_sum = protocol.party2_decrypt(encrypted_sum)

    print(f"交集大小: {intersection_count}")
    print(f"交集值总和: {intersection_sum}")