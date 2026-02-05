# Base64 Decode — Writeup

**カテゴリ**: Crypto | **配点**: 100pts | **難易度**: Easy

---

## コラム

> Base64は1987年にRFC 989で初めて標準化された。名前の由来は64種類の文字（A-Z, a-z, 0-9, +, /）を使うことから。メールの添付ファイル（MIME）やデータURLスキーム、JWTトークンなど、今でも広く使われている。「暗号化」と誤解されがちだが、実際は単なる**エンコーディング**であり、秘密を守る機能は一切ない。

---

## 問題の概要

Base64エンコードされた文字列 `RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259` が与えられる。
これをデコードしてフラグを取得せよ。

---

## キーワード・前提知識

- **Base64** → バイナリデータを64種類のASCII文字で表現するエンコーディング方式
- **エンコーディング** → データの形式を変換すること。暗号化とは異なり、誰でも元に戻せる
- **パディング** → Base64で長さを4の倍数に揃えるために末尾に付与される `=` 文字

---

## 解法ステップ（攻撃者の視点）

### [Step 1] 文字列の観察

与えられた文字列を確認する。

```
RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259
```

**結果:**
- 英数字のみで構成
- `=` パディングなし（長さが4の倍数のため）
- Base64の特徴に合致

> **ポイント:** Base64は `A-Za-z0-9+/=` の65文字のみで構成される。この特徴を覚えておくと、CTFで遭遇した謎の文字列がBase64かどうかすぐに判断できる。

### [Step 2] Base64デコードの実行

**実行コマンド:**
```bash
echo "RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259" | base64 -d
```

**オプション説明:**
- `-d`: デコードモード（`--decode` の短縮形）

**結果:**
```
FLAG{base64_is_not_encryption}
```

> **ポイント:** Linuxでは `base64 -d`、macOSでは `base64 -D` とオプションが異なる場合がある。CyberChef（https://gchq.github.io/CyberChef/）を使えばブラウザ上でも簡単にデコードできる。

### [Step 3] 代替手法（Python）

**実行コマンド:**
```python
python3 -c "import base64; print(base64.b64decode('RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259').decode())"
```

**結果:**
同様に `FLAG{base64_is_not_encryption}` が出力される。

---

## Flag

```
FLAG{base64_is_not_encryption}
```

**和訳・意図:** 「Base64は暗号化ではない」— Base64を暗号化と誤解している人への警告メッセージ。

---

## 防衛者の視点 — この攻撃を防ぐには

### [1] Base64を「暗号化」として使用しない

**なぜ脆弱なのか:**
Base64はデータのエンコーディングに過ぎず、秘密鍵を必要としない。誰でもデコードツールで元のデータを復元できる。

**具体的な対策:**
```bash
# 悪い例: Base64で「暗号化」したつもり
echo "password123" | base64
# cGFzc3dvcmQxMjM= ← 誰でもデコード可能

# 良い例: 適切な暗号化（AES）
openssl enc -aes-256-cbc -salt -in secret.txt -out encrypted.bin -pass pass:mypassword
```

**実務での適用シーン:**
APIトークン、パスワード、個人情報など、秘匿性が必要なデータは必ずAES等の暗号化を使用する。

### [2] 機密データはハッシュ化または暗号化を使用

**なぜ脆弱なのか:**
Base64エンコードされたデータは、通信路上で傍受された場合、即座に内容が読み取られる。

**具体的な対策:**
```bash
# パスワードの保存にはハッシュ化
echo -n "password123" | sha256sum

# 可逆性が必要な場合は暗号化
gpg -c --cipher-algo AES256 secret.txt
```

**実務での適用シーン:**
- パスワード保存: bcrypt, Argon2などのハッシュ関数
- データ転送: TLS/SSL暗号化通信
- ファイル保存: AES暗号化

### [3] セキュリティレビューでBase64の誤用を検出

**なぜ脆弱なのか:**
開発者がBase64を「難読化」目的で使用し、それで十分と誤解しているケースが多い。

**具体的な対策:**
```bash
# コードベースでBase64エンコードされた機密情報を検出
grep -rn "base64" --include="*.py" --include="*.js" | grep -i "password\|secret\|token"
```

**実務での適用シーン:**
コードレビュー時のチェックリストに「Base64で機密情報をエンコードしていないか」を追加する。

---

## 学び・ポイント

- Base64は**エンコーディング**であり、**暗号化**ではない
- CTFではBase64は最初に試すべき定番手法の一つ
- 実務でもBase64を暗号化代わりに使っている脆弱なシステムは多い
- CyberChefやコマンドラインツールで簡単にデコード可能

## 難易度評価

**Easy** - Base64の基本知識があれば即座に解ける入門問題。CTFの最初の一歩として最適。
