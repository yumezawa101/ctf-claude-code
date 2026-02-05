# Base64 Decode (Crypto/100pts)

## 問題概要

この文字列をデコードせよ: `RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259`

## 解法

### 1. 初期調査

与えられた文字列を観察：
- 英数字と`=`で構成される可能性
- 文字列長から Base64 エンコーディングと推測

```
RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259
```

### 2. エンコーディングの特定

Base64 の特徴：
- A-Z, a-z, 0-9, +, / の64文字を使用
- パディングに `=` を使用（今回はなし）
- 4文字 → 3バイトの変換

### 3. デコード実行

```bash
echo "RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259" | base64 -d
```

結果: `FLAG{base64_is_not_encryption}`

## 使用ツール

- base64 (GNU coreutils)
- CyberChef (代替手段)

## 解法コード

```bash
# 方法1: コマンドライン
echo "RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259" | base64 -d

# 方法2: Python
python3 -c "import base64; print(base64.b64decode('RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259').decode())"
```

## Flag

`FLAG{base64_is_not_encryption}`

## 学び・ポイント

- Base64 は**エンコーディング**であり、**暗号化**ではない
- 誰でもデコード可能なため、秘密情報の保護には使えない
- CTFでは Base64 は最初に試すべき定番手法

## 難易度評価

**Easy** - Base64 の基本知識があれば即座に解ける入門問題
