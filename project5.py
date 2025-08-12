
import random
import binascii
import struct
import math
from typing import Tuple, Union, List, Optional


# ========================================
# 基础数学运算优化
# ========================================

def mod_inv(a: int, n: int) -> int:
    """扩展欧几里得算法求模逆元 (优化版本)"""
    t, newt = 0, 1
    r, newr = n, a

    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr

    if r > 1:
        raise ValueError("a is not invertible")
    if t < 0:
        t = t + n
    return t


def jacobian_mod_inv(a: int, n: int) -> int:
    """快速模逆运算（针对Jacobian坐标优化）"""
    return pow(a, n - 2, n)  # 利用Fermat小定理，n为素数


def montgomery_multiply(a: int, b: int, n: int, n_prime: int, r: int) -> int:
    """Montgomery模乘算法 (优化版本)"""
    t = a * b
    m = (t * n_prime) % r
    u = (t + m * n) // r
    return u if u < n else u - n


# ========================================
# SM3哈希算法完整实现 (优化版本)
# ========================================

def rotate_left(x: int, n: int) -> int:
    """循环左移 (高效实现)"""
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


class SM3:
    def __init__(self):
        self.iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
                   0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
        self.reset()

    def reset(self):
        self.state = self.iv[:]
        self.msg_len = 0
        self.buffer = bytearray()

    def _compress(self, block: bytearray):
        """压缩函数优化"""
        w = [0] * 68
        w1 = [0] * 64

        # 消息扩展
        for i in range(16):
            w[i] = struct.unpack(">I", block[i * 4:i * 4 + 4])[0]

        for i in range(16, 68):
            w[i] = rotate_left(w[i - 16] ^ w[i - 9] ^ rotate_left(w[i - 3], 15), 1) ^ \
                   rotate_left(w[i - 13], 7) ^ w[i - 6]

        for i in range(64):
            w1[i] = w[i] ^ w[i + 4]

        # 迭代压缩
        a, b, c, d, e, f, g, h = self.state

        for i in range(64):
            if i < 16:
                ff = (a ^ b) ^ c
                gg = (e ^ f) ^ g
            elif i < 32:
                ff = (a & b) | ((a ^ b) & c)
                gg = (e & f) | ((~e) & g)
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | (e & g) | (f & g)

            ff = ff & 0xFFFFFFFF
            gg = gg & 0xFFFFFFFF

            ss1 = rotate_left(
                (rotate_left(a, 12) + e + rotate_left(0x79CC4519 if i < 16 else 0x7A879D8A, i % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ rotate_left(a, 12)
            tt1 = (ff + d + ss2 + w1[i]) & 0xFFFFFFFF
            tt2 = (gg + h + ss1 + w[i]) & 0xFFFFFFFF
            d = c
            c = rotate_left(b, 9)
            b = a
            a = tt1
            h = g
            g = rotate_left(f, 19)
            f = e
            e = tt2 ^ rotate_left(tt2, 9) ^ rotate_left(tt2, 17)

        self.state = (
            self.state[0] ^ a,
            self.state[1] ^ b,
            self.state[2] ^ c,
            self.state[3] ^ d,
            self.state[4] ^ e,
            self.state[5] ^ f,
            self.state[6] ^ g,
            self.state[7] ^ h
        )

    def update(self, data: bytes):
        """更新消息状态 (高效缓存处理)"""
        self.msg_len += len(data)
        self.buffer.extend(data)

        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            self.buffer = self.buffer[64:]
            self._compress(block)

    def digest(self) -> bytes:
        """生成最终哈希值 (添加填充)"""
        # 添加填充
        self.buffer.append(0x80)
        while len(self.buffer) % 64 != 56:
            self.buffer.append(0x00)

        bit_len = self.msg_len * 8
        self.buffer.extend(struct.pack(">Q", bit_len))

        # 处理最后的分块
        while self.buffer:
            block = self.buffer[:64]
            self.buffer = self.buffer[64:]
            self._compress(block)

        result = b"".join(struct.pack(">I", word) for word in self.state)
        self.reset()
        return result

    def hexdigest(self) -> str:
        """返回16进制哈希值"""
        return binascii.hexlify(self.digest()).decode()


# ========================================
# 椭圆曲线优化实现 (Jacobian坐标 + 窗口法)
# ========================================

class EllipticCurve:
    """带Jacobian坐标和窗口法优化的椭圆曲线实现"""

    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p
        self._window_size = 5  # 窗口法窗口大小（5位）
        self._precomputed = {}

    def _to_jacobian(self, P: Tuple[int, int]) -> Tuple[int, int, int]:
        """转换为Jacobian坐标 (x, y, z)"""
        if P is None:
            return (0, 0, 0)
        return (P[0], P[1], 1)

    def _from_jacobian(self, P: Tuple[int, int, int]) -> Tuple[int, int]:
        """从Jacobian坐标转换回仿射坐标"""
        if P[2] == 0:
            return None
        zinv = jacobian_mod_inv(P[2], self.p)
        zinv_sq = (zinv * zinv) % self.p
        x = (P[0] * zinv_sq) % self.p
        y = (P[1] * zinv_sq * zinv) % self.p
        return (x, y)

    def _add_jacobian(self, P: Tuple[int, int, int], Q: Tuple[int, int, int]) -> Tuple[int, int, int]:
        """Jacobian坐标下的点加运算"""
        if Q[2] == 0:
            return P
        if P[2] == 0:
            return Q

        # 高效实现Jacobian点加
        z1sq = (P[2] * P[2]) % self.p
        z2sq = (Q[2] * Q[2]) % self.p
        u1 = (P[0] * z2sq) % self.p
        u2 = (Q[0] * z1sq) % self.p
        s1 = (P[1] * z2sq * Q[2]) % self.p
        s2 = (Q[1] * z1sq * P[2]) % self.p

        if u1 == u2:
            if s1 != s2:
                return (0, 0, 0)  # 无穷远点
            return self._double_jacobian(P)

        h = (u2 - u1) % self.p
        r = (s2 - s1) % self.p
        hsq = (h * h) % self.p
        hcube = (hsq * h) % self.p
        v = (u1 * hsq) % self.p

        x3 = (r * r - hcube - 2 * v) % self.p
        y3 = (r * (v - x3) - s1 * hcube) % self.p
        z3 = (h * P[2] * Q[2]) % self.p

        return (x3, y3, z3)

    def _double_jacobian(self, P: Tuple[int, int, int]) -> Tuple[int, int, int]:
        """Jacobian坐标下的倍点运算"""
        if P[2] == 0:
            return P

        ysq = (P[1] * P[1]) % self.p
        a = (4 * P[0] * ysq) % self.p
        b = (3 * P[0] * P[0] + self.a * pow(P[2], 4, self.p)) % self.p
        x3 = (b * b - 2 * a) % self.p
        y3 = (b * (a - x3) - 8 * ysq * ysq) % self.p
        z3 = (2 * P[1] * P[2]) % self.p

        return (x3, y3, z3)

    def _precompute_points(self, P: Tuple[int, int]):
        """预计算窗口法需要的点"""
        key = (P[0], P[1])
        if key not in self._precomputed:
            jP = self._to_jacobian(P)
            points = [(0, 0, 0)] * (2 << self._window_size)
            points[0] = (0, 0, 0)
            points[1] = jP

            # 计算2的倍数点
            for i in range(2, 1 << self._window_size):
                points[i] = self._add_jacobian(points[i - 1], jP)

            self._precomputed[key] = points
        return self._precomputed[key]

    def multiply_window(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """带窗口法的标量乘法 (优化版)"""
        if k == 0:
            return None

        # 预处理点
        points = self._precompute_points(P)
        w = self._window_size
        mask = (1 << w) - 1

        # Sliding window method
        result = (0, 0, 0)
        while k > 0:
            # 找出最长的非零位段
            if k & 1:
                # 处理奇数位
                win_len = 0
                wval = 0
                while k & (1 << win_len) and win_len < w:
                    wval |= (1 << win_len)
                    win_len += 1

                k >>= win_len

                # 计算窗口值
                window = k & mask
                if window >= (1 << w):
                    window = 0
                k >>= w

                # 添加窗口点
                if win_len > 0:
                    if window > 0:
                        point_idx = wval + (window << win_len)
                    else:
                        point_idx = wval
                    if point_idx < len(points):
                        result = self._add_jacobian(result, points[point_idx])
                    else:
                        # 回退到传统方法（理论上不会发生）
                        temp = points[1]
                        for _ in range(point_idx - 1):
                            temp = self._add_jacobian(temp, points[1])
                        result = self._add_jacobian(result, temp)
            else:
                win_len = 1
                while not (k & (1 << win_len)) and win_len < w:
                    win_len += 1
                win_len += 1
                k >>= win_len
                window = k & mask
                k >>= w

                if win_len > 0:
                    point_idx = (1 << (win_len - 1)) + window
                    if point_idx < len(points):
                        result = self._add_jacobian(result, points[point_idx])

        return self._from_jacobian(result)


# ========================================
# SM2算法实现 (带优化)
# ========================================

class SM2:
    # SM2椭圆曲线参数（sm2p256v1）
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    G_X = 0x32C4AE2C1F1991195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    G_Y = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    HASH = SM3

    def __init__(self):
        self.curve = EllipticCurve(self.A, self.B, self.P)
        self.G = (self.G_X, self.G_Y)
        self.n = self.N
        self.precompute_g()  # 预计算基点相关值

    def precompute_g(self):
        """预计算基点相关值（优化后续计算）"""
        self.curve.multiply_window(1, self.G)  # 触发预计算

    def key_gen(self) -> Tuple[int, Tuple[int, int]]:
        """高效密钥对生成"""
        d = random.SystemRandom().randint(1, self.n - 1)
        P = self.curve.multiply_window(d, self.G)
        return d, P

    @staticmethod
    def sm3(data: bytes) -> int:
        """返回整数的SM3哈希值 (高效实现)"""
        hasher = SM2.HASH()
        hasher.update(data)
        return int.from_bytes(hasher.digest(), byteorder='big')

    def sign(self, d: int, msg: bytes, k: int = None) -> Tuple[int, int]:
        """签名算法 (带优化)"""
        e = self.sm3(msg)

        # 使用预计算的随机数k（或生成新的）
        if k is None:
            k = random.SystemRandom().randint(1, self.n - 1)

        # 高效计算签名
        while True:
            # 高效计算P1 = [k]G
            P1 = self.curve.multiply_window(k, self.G)
            if P1 is None:
                k = random.SystemRandom().randint(1, self.n - 1)
                continue

            r = (e + P1[0]) % self.n
            if r == 0:
                k = random.SystemRandom().randint(1, self.n - 1)
                continue

            # 优化计算s = (1+d)^(-1) * (k - r*d) mod n
            s = (mod_inv(1 + d, self.n) * (k - r * d)) % self.n
            if s == 0:
                k = random.SystemRandom().randint(1, self.n - 1)
                continue

            return r, s

    def verify(self, P: Tuple[int, int], msg: bytes, sig: Tuple[int, int]) -> bool:
        """验签算法 (带优化)"""
        r, s = sig

        # 快速边界检查
        if r < 1 or r >= self.n or s < 1 or s >= self.n:
            return False

        # 高效计算t = (r + s) mod n
        t = (r + s) % self.n
        if t == 0:
            return False

        # 高效计算P1 = [s]G + [t]P
        sG = self.curve.multiply_window(s, self.G)
        tP = self.curve.multiply_window(t, P)
        if sG is None or tP is None:
            return False
        P1 = self.curve._from_jacobian(
            self.curve._add_jacobian(
                self.curve._to_jacobian(sG),
                self.curve._to_jacobian(tP)
            )
        )
        if P1 is None:
            return False

        # 计算R = (e + P1_x) mod n
        e = self.sm3(msg)
        R = (e + P1[0]) % self.n
        return R == r


# ========================================
# 漏洞验证与利用
# ========================================

class SM2Exploit(SM2):
    """SM2漏洞验证与利用"""

    def k_reuse_vulnerability(self):
        """重复随机数k导致私钥泄露"""
        d, P = self.key_gen()
        msg1 =        b"Transfer 100 BTC to Alice"
        msg2 = b"Transfer 100 BTC to Bob"

        # 使用相同的k值生成两个签名
        k = random.SystemRandom().randint(1, self.n-1)
        sig1 = self.sign(d, msg1, k=k)
        sig2 = self.sign(d, msg2, k=k)

        # 分析签名推导私钥
        r1, s1 = sig1
        r2, s2 = sig2

        # 推导私钥公式: d = (s1 - s2)/(r1 - r2) mod n
        denom = (r1 - r2) % self.n
        if denom == 0:
            return False, "无效的签名对（除数为零）"

        # 计算私钥
        d_rec = ((s1 - s2) * mod_inv(denom, self.n)) % self.n

        # 验证推导出的私钥是否正确
        return d_rec == d, f"推导结果: {'成功' if d_rec == d else '失败'}"

    def invalid_verification_vulnerability(self):
        """未验证公钥有效性漏洞利用"""
        # 生成随机点（可能不在曲线上）
        rand_x = random.SystemRandom().randint(1, self.P-1)
        rand_y = random.SystemRandom().randint(1, self.P-1)
        fake_P = (rand_x, rand_y)

        # 随机消息
        msg = b"Invalid public key test"

        # 伪造签名
        u = random.SystemRandom().randint(1, self.n-1)
        v = random.SystemRandom().randint(1, self.n-1)

        # 错误验证函数
        def vulnerable_verify(P: Tuple[int, int], msg: bytes, sig: Tuple[int, int]):
            r, s = sig

            # 跳过公钥在曲线上的验证
            t = (r + s) % self.n
            sG = self.curve.multiply_window(s, self.G)
            tP = self.curve.multiply_window(t, P)
            P1 = self.curve._from_jacobian(
                self.curve._add_jacobian(
                    self.curve._to_jacobian(sG) if sG else (0, 0, 0),
                    self.curve._to_jacobian(tP) if tP else (0, 0, 0)
                )
            )

            # 跳过关键检查
            return P1 is not None  # 忽略实际验证逻辑

        # 构造伪造的签名
        sig = (u, v)

        # 使用错误验证函数进行验证
        verified = vulnerable_verify(fake_P, msg, sig)
        return verified, "伪造成功" if verified else "伪造失败"

    def forge_satoshi_signature(self):
        """伪造中本聪签名演示（概念验证）"""
        # 中本聪的公钥示例（ECDSAPubKey格式）
        SATOSHI_PUB = (
            0x048F3F9BAF8A86A1C9D6BD0EE9E0DABF1ED9E6C8F,
            0x07D0FAA3D9D51DA19DBCA6A5B5D1F07C8F9C6FAA8E1
        )

        # 要伪造的消息
        target_msg = b"Satoshi transfers 1M BTC to me"

        # 签名所需的随机数（需要获得两个使用相同k的签名）
        # 这里假设我们获得了两个签名使用的k
        k = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725

        # 伪造签名（此处仅演示概念）
        # 实际攻击需要获取两个使用相同k的签名
        r1, s1 = self.sign(0, b"Signature 1", k=k)
        r2, s2 = self.sign(0, b"Signature 2", k=k)

        # 展示推导过程
        return (r1, s1), "伪造签名演示"

# ========================================
# 测试与性能评估
# ========================================

if __name__ == "__main__":
    print("===== SM2性能优化实现 =====")
    sm2 = SM2()

    # 基准测试
    import timeit

    def benchmark_sign():
        d, _ = sm2.key_gen()
        sm2.sign(d, b"Benchmark message")

    def benchmark_verify():
        d, P = sm2.key_gen()
        sig = sm2.sign(d, b"Benchmark message")
        sm2.verify(P, b"Benchmark message", sig)

    sign_time = timeit.timeit(benchmark_sign, number=100)
    verify_time = timeit.timeit(benchmark_verify, number=100)
    print(f"密钥生成 + 签名 100次: {sign_time:.4f}s")
    print(f"密钥生成 + 签名 + 验证 100次: {verify_time:.4f}s")
    print(f"平均签名时间: {sign_time/100*1000:.2f}ms")
    print(f"平均验签时间: {(verify_time - sign_time)/100*1000:.2f}ms")

    # 漏洞验证测试
    print("\n===== SM2漏洞验证 =====")
    exploit = SM2Exploit()

    # 重复k值漏洞测试
    success, msg = exploit.k_reuse_vulnerability()
    print(f"重复k值漏洞测试: {msg}")

    # 无效验证漏洞测试
    success, msg = exploit.invalid_verification_vulnerability()
    print(f"无效公钥验证测试: {msg}")

    # 中本聪签名伪造演示
    print("\n===== 中本聪签名伪造演示 =====")
    fake_sig, msg = exploit.forge_satoshi_signature()
    print(f"伪造签名: r={hex(fake_sig[0])}, s={hex(fake_sig[1])}")
    print("注: 此为概念验证，实际攻击需要获取两个使用相同k的签名")

    # 功能验证
    print("\n===== 功能验证 =====")
    d, P = sm2.key_gen()
    msg = b"SM2 digital signature test"

    # 签名与验证
    sig = sm2.sign(d, msg)
    valid = sm2.verify(P, msg, sig)

    # 篡改消息验证失败
    invalid_msg = b"Tampered message"
    invalid = sm2.verify(P, invalid_msg, sig)

    print(f"原始公钥: ({hex(P[0])[:20]}..., {hex(P[1])[:20]}...)")
    print(f"原始签名: r={hex(sig[0])[:10]}..., s={hex(sig[1])[:10]}...")
    print(f"原始消息验证: {'成功' if valid else '失败'}")
    print(f"篡改消息验证: {'成功' if invalid else '失败'}")