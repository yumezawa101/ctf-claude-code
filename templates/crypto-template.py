#!/usr/bin/env python3
"""
CTF Crypto テンプレート
使い方: このファイルをコピーして問題ごとにカスタマイズ
"""
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, GCD
import base64
import codecs

# === Base64 / Hex デコード ===
def decode_base64(s):
    return base64.b64decode(s)

def decode_hex(s):
    return bytes.fromhex(s)

# === XOR ===
def xor_single(data, key):
    """単一キーXOR"""
    return bytes([b ^ key for b in data])

def xor_repeat(data, key):
    """繰り返しキーXOR"""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_find_key(ciphertext, known_plaintext):
    """既知平文攻撃でXORキーを特定"""
    return bytes([c ^ p for c, p in zip(ciphertext, known_plaintext)])

# === RSA 基本 ===
def rsa_decrypt(c, d, n):
    """RSA復号"""
    m = pow(c, d, n)
    return long_to_bytes(m)

def rsa_decrypt_with_pq(c, e, p, q):
    """p, qが既知の場合のRSA復号"""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return rsa_decrypt(c, d, n)

# === RSA 攻撃 ===
def rsa_low_exponent(c, e=3):
    """低指数攻撃 (e=3, 小さいm)"""
    import gmpy2
    m, exact = gmpy2.iroot(c, e)
    if exact:
        return long_to_bytes(int(m))
    return None

def rsa_common_modulus(c1, c2, e1, e2, n):
    """Common Modulus Attack (同じn, 異なるe)"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, s1, s2 = extended_gcd(e1, e2)
    if s1 < 0:
        s1 = -s1
        c1 = inverse(c1, n)
    if s2 < 0:
        s2 = -s2
        c2 = inverse(c2, n)
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return long_to_bytes(m)

def fermat_factor(n):
    """Fermat法 (pとqが近い場合)"""
    import gmpy2
    a = gmpy2.isqrt(n) + 1
    b2 = a * a - n
    while not gmpy2.is_square(b2):
        a += 1
        b2 = a * a - n
    b = gmpy2.isqrt(b2)
    return int(a - b), int(a + b)

# === シーザー暗号 / ROT ===
def caesar(text, shift):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

def rot13(text):
    return codecs.decode(text, 'rot_13')

# === メイン ===
if __name__ == '__main__':
    # === RSA例 ===
    # n = ...
    # e = 65537
    # c = ...
    # p, q = ...  # factordb.com で取得
    # print(rsa_decrypt_with_pq(c, e, p, q))

    # === XOR例 ===
    # ct = bytes.fromhex('...')
    # for key in range(256):
    #     pt = xor_single(ct, key)
    #     if b'flag' in pt.lower():
    #         print(f"Key: {key}, PT: {pt}")

    # === Base64例 ===
    # print(decode_base64('RkxBR3t0ZXN0fQ=='))

    pass
