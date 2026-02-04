---
name: ctf-recon
description: URLまたはファイルに対して初手偵察を自動実行する
---

# 自動偵察

## URL指定時
```bash
# 基本情報
curl -v [URL] 2>&1 | head -50

# ソースコード検索
curl -s [URL] | grep -i "flag\|ctf\|hint\|comment\|<!--"

# 隠しファイル
curl -s [URL]/robots.txt
curl -s [URL]/.git/HEAD
curl -s [URL]/sitemap.xml
curl -s [URL]/.env
curl -s [URL]/backup.zip
curl -s [URL]/flag.txt

# ヘッダー詳細
curl -I [URL]
```

## ファイル指定時
```bash
# 基本情報
file [filename]
strings [filename] | grep -i "flag\|ctf" | head -20
exiftool [filename]

# バイナリ解析
binwalk -e [filename]
xxd [filename] | head -50

# ファイル形式別
# PNG: zsteg [filename]
# JPG: steghide info [filename]
# ZIP: zipinfo [filename]
# PCAP: tshark -r [filename] -Y "http" | head -20
```

## 使用方法
```
/ctf-recon https://targetctf_solutions/challenge
/ctf-recon ./challenge.png
```

## 出力
- 発見した情報のサマリー
- 推奨する攻撃ベクトル
- 次のステップ提案
