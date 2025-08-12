import numpy as np
from PIL import Image, ImageEnhance, ImageOps
import pywt
from skimage.util import random_noise
import cv2
import matplotlib.pyplot as plt
import os


class DWTWatermark:
    def __init__(self, strength=0.1):
        self.strength = strength  # 水印嵌入强度系数
        self.watermark_size = None

    def _arnold_transform(self, img, key):
        """Arnold置乱算法"""
        N = min(img.shape)
        out = np.zeros_like(img)
        for _ in range(key):
            for i in range(N):
                for j in range(N):
                    ni = (i + j) % N
                    nj = (i + 2 * j) % N
                    out[ni, nj] = img[i, j]
            img = out.copy()
        return out

    def _inverse_arnold(self, img, key):
        """Arnold逆变换"""
        N = min(img.shape)
        out = np.zeros_like(img)
        for _ in range(key):
            for i in range(N):
                for j in range(N):
                    ni = (i - 2 * j) % N
                    nj = (2 * i - j) % N
                    out[ni, nj] = img[i, j]
            img = out.copy()
        return out

    def embed(self, host_path, watermark_path, output_path):
        """嵌入水印"""
        host = Image.open(host_path).convert('L')
        watermark = Image.open(watermark_path).convert('1')
        host_arr = np.array(host, dtype=np.float32)
        wm_arr = np.array(watermark, dtype=np.float32)

        # 调整水印大小 (使用正方形区域)
        size = min(host_arr.shape) // 4
        wm_arr = np.array(Image.fromarray(wm_arr).resize((size, size)))
        self.watermark_size = wm_arr.shape

        # Arnold置乱
        key = 10  # 置乱密钥
        scrambled = self._arnold_transform(wm_arr, key)

        # DWT分解
        cA, (cH, cV, cD) = pywt.dwt2(host_arr, 'haar')

        # 嵌入水印到LL低频子带
        cA_wm = cA.copy()
        cA_wm[:size, :size] += scrambled * self.strength * cA[:size, :size].std()

        # IDWT重构
        watermarked = pywt.idwt2((cA_wm, (cH, cV, cD)), 'haar')
        watermarked = np.clip(watermarked, 0, 255).astype(np.uint8)

        Image.fromarray(watermarked).save(output_path)
        return watermarked

    def extract(self, image_path, original_host=None, key=10):
        """提取水印"""
        img_arr = np.array(Image.open(image_path).convert('L'), dtype=np.float32)

        # DWT分解
        cA, (cH, cV, cD) = pywt.dwt2(img_arr, 'haar')

        if original_host is None:
            # 盲提取 (仅使用含水印图像)
            extracted = cA[:self.watermark_size[0], :self.watermark_size[1]]
            extracted = extracted - extracted.mean()
        else:
            # 非盲提取 (使用原始宿主图像)
            orig_arr = np.array(Image.open(original_host).convert('L'), dtype=np.float32)
            cA_orig, _ = pywt.dwt2(orig_arr, 'haar')
            extracted = (cA - cA_orig)[:self.watermark_size[0], :self.watermark_size[1]]

        # Arnold逆变换
        extracted = self._inverse_arnold(extracted, key)

        # 二值化水印
        extracted = (extracted > extracted.mean()).astype(np.uint8) * 255
        return Image.fromarray(extracted)


class RobustnessTester:
    """水印鲁棒性测试工具"""

    @staticmethod
    def rotate(image_path, angle, output_path):
        img = Image.open(image_path)
        rotated = img.rotate(angle, expand=True)
        rotated.save(output_path)
        return rotated

    @staticmethod
    def crop(image_path, ratio, output_path):
        img = np.array(Image.open(image_path))
        h, w = img.shape[:2]
        cropped = img[int(h * ratio):int(h * (1 - ratio)),
                  int(w * ratio):int(w * (1 - ratio))]
        Image.fromarray(cropped).save(output_path)
        return cropped

    @staticmethod
    def adjust_contrast(image_path, factor, output_path):
        img = Image.open(image_path)
        enhancer = ImageEnhance.Contrast(img)
        enhanced = enhancer.enhance(factor)
        enhanced.save(output_path)
        return enhanced

    @staticmethod
    def add_noise(image_path, var, output_path):
        img = np.array(Image.open(image_path))
        noisy = random_noise(img, var=var)
        noisy = (255 * noisy).astype(np.uint8)
        Image.fromarray(noisy).save(output_path)
        return noisy

    @staticmethod
    def jpeg_compress(image_path, quality, output_path):
        img = Image.open(image_path)
        img.save(output_path, "JPEG", quality=quality)

    @staticmethod
    def scale(image_path, factor, output_path):
        img = Image.open(image_path)
        w, h = img.size
        scaled = img.resize((int(w * factor), int(h * factor)), Image.BICUBIC)
        scaled.save(output_path)
        return scaled

    @staticmethod
    def flip(image_path, direction, output_path):
        img = Image.open(image_path)
        flipped = ImageOps.mirror(img) if direction == 'horizontal' else ImageOps.flip(img)
        flipped.save(output_path)
        return flipped

    @staticmethod
    def calculate_similarity(original_wm, extracted_wm):
        """计算归一化相关系数(NC)"""
        orig = np.array(original_wm).flatten()
        extr = np.array(extracted_wm.resize(original_wm.size)).flatten()
        corr = np.corrcoef(orig, extr)[0, 1]
        return max(0, corr)  # 相关系数在-1~1之间，负相关视为0


# 示例用法
if __name__ == "__main__":
    # 初始化
    dwt_wm = DWTWatermark(strength=0.15)

    # 1. 嵌入水印
    embedded = dwt_wm.embed('host.jpg', 'watermark.png', 'watermarked.jpg')

    # 2. 鲁棒性测试
    tester = RobustnessTester()
    attacks = {
        'rotate_5': lambda: tester.rotate('watermarked.jpg', 5, 'rotated.jpg'),
        'crop_10': lambda: tester.crop('watermarked.jpg', 0.1, 'cropped.jpg'),
        'contrast_1.5': lambda: tester.adjust_contrast('watermarked.jpg', 1.5, 'contrast.jpg'),
        'noise_0.01': lambda: tester.add_noise('watermarked.jpg', 0.01, 'noisy.jpg'),
        'jpeg_30': lambda: tester.jpeg_compress('watermarked.jpg', 30, 'compressed.jpg'),
        'scale_0.8': lambda: tester.scale('watermarked.jpg', 0.8, 'scaled.jpg'),
        'flip_h': lambda: tester.flip('watermarked.jpg', 'horizontal', 'flipped.jpg')
    }

    # 原始水印
    orig_wm = Image.open('watermark.png').convert('1')

    # 测试各种攻击
    results = {}
    for name, attack_fn in attacks.items():
        # 执行攻击
        attack_fn()
        # 提取水印
        extracted = dwt_wm.extract(name.split('_')[0] + '.jpg', 'host.jpg')
        extracted.save(f'extracted_{name}.png')
        # 计算相似度
        similarity = tester.calculate_similarity(orig_wm, extracted)
        results[name] = similarity

    # 打印测试结果
    print("鲁棒性测试结果 (归一化相关系数):")
    for attack, score in results.items():
        print(f"{attack}: {score:.4f}")