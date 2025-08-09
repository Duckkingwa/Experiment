import struct
from typing import Union, Optional
from enum import Enum, auto

class Mode(Enum):
    ECB = auto()
    CBC = auto()
    CTR = auto()

class SM4:
    """
    优化的SM4加密算法实现，支持ECB、CBC和CTR模式
    """
    # 常量定义
    BLOCK_SIZE = 16
    KEY_SIZE = 16
    ROUNDS = 32

    # S盒
    SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]

    # 预计算SBOX查找表（优化性能）
    SBOX_TABLE = [SBOX] * 4  # 为每个字节位置准备一个SBOX

    # 系统参数FK
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

    # 固定参数CK
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]

    def __init__(self, key: Union[bytes, bytearray], mode: Mode = Mode.ECB,
                 iv: Optional[Union[bytes, bytearray]] = None):
        """
        初始化SM4实例
        :param key: 16字节的密钥
        :param mode: 工作模式(ECB/CBC/CTR)
        :param iv: 初始化向量(CBC和CTR模式需要)
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes long")

        self.mode = mode
        self.key = bytes(key)

        if mode in (Mode.CBC, Mode.CTR):
            if iv is None:
                raise ValueError(f"{mode.name} mode requires an IV")
            if len(iv) != self.BLOCK_SIZE:
                raise ValueError(f"IV must be {self.BLOCK_SIZE} bytes long")
            self.iv = bytes(iv)
        else:
            self.iv = None

        # 预计算轮密钥
        self.encrypt_rk = self._expand_key(self.key)
        self.decrypt_rk = self.encrypt_rk[::-1]  # 解密是加密的逆过程

    @classmethod
    def _left_rotate(cls, x: int, n: int) -> int:
        """优化的循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @classmethod
    def _tau(cls, a: int) -> int:
        """优化的非线性变换τ(.)，使用预计算的SBOX表"""
        # 使用位操作和预计算表加速
        return (cls.SBOX_TABLE[0][(a >> 24) & 0xFF] << 24 |
                cls.SBOX_TABLE[1][(a >> 16) & 0xFF] << 16 |
                cls.SBOX_TABLE[2][(a >> 8) & 0xFF] << 8 |
                cls.SBOX_TABLE[3][a & 0xFF])

    @classmethod
    def _l(cls, b: int) -> int:
        """优化的线性变换L"""
        return (b ^ cls._left_rotate(b, 2) ^
                cls._left_rotate(b, 10) ^
                cls._left_rotate(b, 18) ^
                cls._left_rotate(b, 24))

    @classmethod
    def _l_prime(cls, b: int) -> int:
        """优化的线性变换L'"""
        return b ^ cls._left_rotate(b, 13) ^ cls._left_rotate(b, 23)

    @classmethod
    def _t(cls, x: int) -> int:
        """优化的合成变换T"""
        return cls._l(cls._tau(x))

    @classmethod
    def _t_prime(cls, x: int) -> int:
        """优化的合成变换T'"""
        return cls._l_prime(cls._tau(x))

    @classmethod
    def _f(cls, x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
        """优化的轮函数F"""
        return x0 ^ cls._t(x1 ^ x2 ^ x3 ^ rk)

    @classmethod
    def _expand_key(cls, key: Union[bytes, bytearray]) -> list[int]:
        """优化的密钥扩展算法"""
        # 将密钥转换为4个32位字
        mk = [0] * 4
        for i in range(4):
            mk[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]

        # 生成中间密钥K
        k = [0] * 36
        for i in range(4):
            k[i] = mk[i] ^ cls.FK[i]

        # 生成轮密钥rk
        rk = [0] * cls.ROUNDS
        for i in range(cls.ROUNDS):
            k[i + 4] = k[i] ^ cls._t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ cls.CK[i])
            rk[i] = k[i + 4]

        return rk

    def _crypt_block(self, block: Union[bytes, bytearray], rk: list[int]) -> bytes:
        """优化的块加密/解密核心函数"""
        # 将输入数据转换为4个32位字
        x = [0] * 36
        for i in range(4):
            x[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) | (block[4 * i + 2] << 8) | block[4 * i + 3]

        # 32轮迭代运算
        for i in range(self.ROUNDS):
            x[i + 4] = self._f(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i])

        # 反序变换并返回结果
        return struct.pack('>4I', x[35], x[34], x[33], x[32])

    @staticmethod
    def _pad(data: Union[bytes, bytearray]) -> bytes:
        """PKCS#7填充"""
        pad_len = SM4.BLOCK_SIZE - (len(data) % SM4.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(data: Union[bytes, bytearray]) -> bytes:
        """PKCS#7去填充"""
        pad_len = data[-1]
        if pad_len > SM4.BLOCK_SIZE or pad_len <= 0:
            raise ValueError("Invalid padding")
        if not all(b == pad_len for b in data[-pad_len:]):
            raise ValueError("Invalid padding")
        return data[:-pad_len]

    def encrypt(self, plaintext: Union[bytes, bytearray],
                padding: bool = True) -> bytes:
        """
        加密数据
        :param plaintext: 要加密的数据
        :param padding: 是否自动添加PKCS#7填充
        :return: 密文
        """
        if not plaintext:
            return b''

        data = bytes(plaintext)
        if padding:
            data = self._pad(data)

        # 根据模式处理数据
        if self.mode == Mode.ECB:
            return self._encrypt_ecb(data)
        elif self.mode == Mode.CBC:
            return self._encrypt_cbc(data)
        elif self.mode == Mode.CTR:
            return self._encrypt_ctr(data)
        else:
            raise ValueError("Unsupported mode")

    def _encrypt_ecb(self, data: bytes) -> bytes:
        """ECB模式加密"""
        if len(data) % self.BLOCK_SIZE != 0:
            raise ValueError("Data length must be multiple of block size")

        result = bytearray()
        for i in range(0, len(data), self.BLOCK_SIZE):
            block = data[i:i + self.BLOCK_SIZE]
            encrypted = self._crypt_block(block, self.encrypt_rk)
            result.extend(encrypted)
        return bytes(result)

    def _encrypt_cbc(self, data: bytes) -> bytes:
        """CBC模式加密"""
        if len(data) % self.BLOCK_SIZE != 0:
            raise ValueError("Data length must be multiple of block size")

        result = bytearray()
        prev_block = self.iv

        for i in range(0, len(data), self.BLOCK_SIZE):
            block = data[i:i + self.BLOCK_SIZE]
            # CBC模式：先与前一个密文块异或
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = self._crypt_block(xored, self.encrypt_rk)
            result.extend(encrypted)
            prev_block = encrypted

        return bytes(result)

    def _encrypt_ctr(self, data: bytes) -> bytes:
        """CTR模式加密"""
        result = bytearray()
        counter = int.from_bytes(self.iv, 'big')

        for i in range(0, len(data), self.BLOCK_SIZE):
            # 生成密钥流
            counter_block = counter.to_bytes(self.BLOCK_SIZE, 'big')
            keystream = self._crypt_block(counter_block, self.encrypt_rk)

            # 处理当前块
            block = data[i:i + self.BLOCK_SIZE]
            encrypted = bytes(a ^ b for a, b in zip(block, keystream))
            result.extend(encrypted)

            # 计数器递增
            counter += 1

        return bytes(result)

    def decrypt(self, ciphertext: Union[bytes, bytearray],
                padding: bool = True) -> bytes:
        """
        解密数据

        :param ciphertext: 要解密的数据
        :param padding: 是否自动去除PKCS#7填充
        :return: 明文
        """
        if not ciphertext:
            return b''

        data = bytes(ciphertext)
        if len(data) % self.BLOCK_SIZE != 0 and self.mode != Mode.CTR:
            raise ValueError("Ciphertext length must be multiple of block size")

        # 根据模式处理数据
        if self.mode == Mode.ECB:
            result = self._decrypt_ecb(data)
        elif self.mode == Mode.CBC:
            result = self._decrypt_cbc(data)
        elif self.mode == Mode.CTR:
            result = self._decrypt_ctr(data)
        else:
            raise ValueError("Unsupported mode")

        # 去除填充
        if padding and self.mode != Mode.CTR:
            try:
                result = self._unpad(result)
            except ValueError as e:
                raise ValueError("Decryption failed: invalid padding") from e

        return result

    def _decrypt_ecb(self, data: bytes) -> bytes:
        """ECB模式解密"""
        result = bytearray()
        for i in range(0, len(data), self.BLOCK_SIZE):
            block = data[i:i + self.BLOCK_SIZE]
            decrypted = self._crypt_block(block, self.decrypt_rk)
            result.extend(decrypted)
        return bytes(result)

    def _decrypt_cbc(self, data: bytes) -> bytes:
        """CBC模式解密"""
        result = bytearray()
        prev_block = self.iv

        for i in range(0, len(data), self.BLOCK_SIZE):
            block = data[i:i + self.BLOCK_SIZE]
            decrypted = self._crypt_block(block, self.decrypt_rk)
            # CBC模式：解密后再与前一个密文块异或
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            result.extend(xored)
            prev_block = block

        return bytes(result)

    def _decrypt_ctr(self, data: bytes) -> bytes:
        """CTR模式解密（与加密过程相同）"""
        return self._encrypt_ctr(data)


# 示例用法
if __name__ == "__main__":
    # 测试数据
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv = bytes.fromhex("00000000000000000000000000000000")
    plaintext = b"Hello, SM4! This is a test message."

    print("原始明文:", plaintext)

    # 测试ECB模式
    print("\nECB模式测试:")
    sm4_ecb = SM4(key, Mode.ECB)
    ciphertext = sm4_ecb.encrypt(plaintext)
    print("加密结果:", ciphertext.hex())
    decrypted = sm4_ecb.decrypt(ciphertext)
    print("解密结果:", decrypted.decode())

    # 测试CBC模式
    print("\nCBC模式测试:")
    sm4_cbc = SM4(key, Mode.CBC, iv)
    ciphertext = sm4_cbc.encrypt(plaintext)
    print("加密结果:", ciphertext.hex())
    decrypted = sm4_cbc.decrypt(ciphertext)
    print("解密结果:", decrypted.decode())

    # 测试CTR模式
    print("\nCTR模式测试:")
    sm4_ctr = SM4(key, Mode.CTR, iv)
    ciphertext = sm4_ctr.encrypt(plaintext)
    print("加密结果:", ciphertext.hex())
    decrypted = sm4_ctr.decrypt(ciphertext)
    print("解密结果:", decrypted.decode())