# /ctf-hint - 学習データからヒントを取得

問題の特徴からマッチするヒントを学習データベースから検索・提示する。

## 使用法

```
/ctf-hint <問題の特徴やキーワード>
/ctf-hint --category <カテゴリ>
/ctf-hint --list
```

## 引数

| 引数 | 説明 |
|------|------|
| `<問題の特徴>` | 問題文やファイル形式などの特徴 |
| `--category <cat>` | カテゴリ指定（web/crypto/forensics/pwn/osint） |
| `--list` | 全ヒントを一覧表示 |

## 使用例

```bash
# 問題の特徴からヒントを取得
/ctf-hint "ログインフォームがある"
# → SQLi基本ペイロード（' OR 1=1--）を試す

# PNG画像が添付されている場合
/ctf-hint "PNG画像"
# → zsteg → exiftool → binwalk の順で実行

# RSA問題のヒント
/ctf-hint "n, e, c パラメータ"
# → RSA問題。nをfactordbで素因数分解

# カテゴリ別にヒント一覧
/ctf-hint --category crypto

# 全ヒント一覧
/ctf-hint --list
```

## 実行フロー

1. **キーワードマッチング**
   - `skills/ctf-learning/instincts.json` から類似パターンを検索
   - `skills/ctf-knowledge/*-patterns.md` から関連情報を取得

2. **信頼度順にソート**
   - confidence値が高い順に表示
   - 過去の成功回数（source_count）も考慮

3. **関連リソースの提示**
   - オンラインツール（CyberChef, FactorDB等）
   - PayloadsAllTheThings等の参照先

## データソース

### instincts.json（自動学習）

```json
{
  "trigger": "トリガー条件",
  "action": "推奨アクション",
  "category": "カテゴリ",
  "confidence": 0.95
}
```

### カテゴリ別パターンファイル

| ファイル | 内容 |
|----------|------|
| `web-patterns.md` | SQLi, XSS, SSRF等 |
| `crypto-patterns.md` | RSA, AES, XOR等 |
| `forensics-patterns.md` | ステガノ, メモリ, PCAP等 |
| `pwn-patterns.md` | BOF, ROP, Format String等 |
| `osint-patterns.md` | 画像調査, Dorking等 |

## ヒントの追加方法

### 手動追加

`skills/ctf-learning/instincts.json` を編集：

```json
{
  "trigger": "新しいトリガー条件",
  "action": "推奨アクション",
  "category": "web",
  "confidence": 0.80,
  "source_count": 0
}
```

### 自動学習

セッション終了時に `ctf-session-save.js` が解法パターンを自動抽出し、
`instincts.json` に追加される。

## クイックリファレンス

### よく使うヒント

| 特徴 | ヒント |
|------|--------|
| Base64文字列 | Base64デコードを試す |
| PNG画像 | zsteg → exiftool → binwalk |
| JPG画像 | steghide（パスワード空）→ exiftool |
| ログインフォーム | SQLi基本ペイロード |
| n, e, c パラメータ | RSA、factordbで素因数分解 |
| pcapファイル | tshark/wiresharkでHTTP確認 |
| ELFバイナリ | checksec → file → strings |
| nc接続先 | まず接続して挙動確認 |

### オンラインリソース

- **CyberChef**: https://gchq.github.io/CyberChef/
- **FactorDB**: http://factordb.com/
- **CrackStation**: https://crackstation.net/
- **GTFOBins**: https://gtfobins.github.io/
- **HackTricks**: https://book.hacktricks.xyz/
