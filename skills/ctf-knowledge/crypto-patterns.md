# Crypto CTF パターン集

## エンコーディング

### Base64
```python
import base64
base64.b64decode("SGVsbG8=")  # b'Hello'
```

### Hex
```python
bytes.fromhex("48656c6c6f")  # b'Hello'
```

### ROT13
```python
import codecs
codecs.decode("Uryyb", "rot_13")  # 'Hello'
```

## RSA

### 基本公式
```
暗号化: c = m^e mod n
復号: m = c^d mod n
d = inverse(e, phi)
phi = (p-1)(q-1)
```

### 基本解読スクリプト
```python
from Crypto.Util.number import long_to_bytes, inverse

n = ...  # 公開鍵の一部
e = ...  # 公開指数（通常65537）
c = ...  # 暗号文
p = ...  # 素因数1（factordbで取得）
q = ...  # 素因数2

phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

### 攻撃パターン

#### 小さいe（e=3）
```python
import gmpy2
m = gmpy2.iroot(c, 3)[0]
```

#### Wiener's Attack
```python
# d が小さい場合
from Crypto.PublicKey import RSA
# RsaCtfTool を使用
```

#### Common Modulus Attack
```python
# 同じnで異なるeで暗号化された場合
def common_modulus(n, e1, e2, c1, c2):
    g, a, b = extended_gcd(e1, e2)
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

## XOR

```python
def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# シングルバイトXOR総当たり
for k in range(256):
    result = bytes([b ^ k for b in ciphertext])
    if b'flag' in result.lower():
        print(k, result)
```

## AES

### ECBの脆弱性
- 同じ平文ブロック → 同じ暗号文ブロック
- ブロック入れ替え攻撃が可能

### Padding Oracle
```python
# padbuster または手動実装
```
