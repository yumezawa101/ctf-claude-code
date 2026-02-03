# OSINT CTF パターン集

## 画像調査

### EXIF情報
```bash
exiftool [image]
# GPS座標があれば Google Maps で確認
```

### 逆画像検索
- Google Images: https://images.google.com/
- Yandex: https://yandex.com/images/
- TinEye: https://tineye.com/

### 画像から位置特定
1. 看板・標識の言語を確認
2. 建物の特徴、電柱の形状
3. 車のナンバープレート
4. Google Street View で照合

## ユーザー名調査

```bash
# 複数SNS横断検索
sherlock [username]

# 手動確認
# Twitter: https://twitter.com/[username]
# Instagram: https://instagram.com/[username]
# GitHub: https://github.com/[username]
# LinkedIn: https://linkedin.com/in/[username]
```

## ドメイン/IP調査

```bash
whois [domain]
dig [domain] ANY
dig [domain] TXT
nslookup [domain]
host -a [domain]

# 履歴
# SecurityTrails
# Shodan: https://shodan.io/
# Censys: https://censys.io/
```

## Google Dorking

```
# 特定サイト内検索
site:example.com "password"

# ファイルタイプ
filetype:pdf site:example.com

# タイトル/URL
intitle:"index of"
inurl:admin

# 除外
site:example.com -www

# キャッシュ
cache:example.com
```

## Webアーカイブ

- Wayback Machine: https://web.archive.org/
- 使い方: `https://web.archive.org/web/*/example.com`

## メタデータ

### PDF
```bash
pdfinfo [file.pdf]
exiftool [file.pdf]
strings [file.pdf] | grep -i author
```

### Office文書
```bash
exiftool [file.docx]
unzip -l [file.docx]  # XMLを確認
```

## ソーシャルメディア

### Twitter
- 高度な検索: https://twitter.com/search-advanced
- `from:username since:2023-01-01 until:2023-12-31`

### GitHub
- コミット履歴に機密情報がないか確認
- Issues, Wiki もチェック
