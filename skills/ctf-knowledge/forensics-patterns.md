# Forensics CTF パターン集

## 初手コマンド

```bash
file [filename]
strings [filename] | grep -iE "flag|ctf|password"
exiftool [filename]
binwalk -e [filename]
xxd [filename] | head -100
```

## 画像ステガノグラフィ

### PNG
```bash
zsteg [image.png]
zsteg -a [image.png]  # 全チャンネル
pngcheck -v [image.png]
```

### JPG
```bash
steghide info [image.jpg]
steghide extract -sf [image.jpg]  # パスワード空
steghide extract -sf [image.jpg] -p "password"
stegseek [image.jpg] rockyou.txt  # 辞書攻撃
```

### 共通
```bash
exiftool [image]  # EXIF情報
strings [image] | grep -i flag
binwalk -e [image]  # 埋め込みファイル抽出
```

## PCAP解析

### 基本
```bash
tshark -r [file.pcap] -Y "http" | head -50
tshark -r [file.pcap] -Y "http.request.method == POST"
tshark -r [file.pcap] -Y "tcp contains flag"
```

### HTTPオブジェクト抽出
```bash
tshark -r [file.pcap] --export-objects http,./extracted/
```

### 認証情報
```bash
tshark -r [file.pcap] -Y "http.authbasic"
tshark -r [file.pcap] -Y "ftp.request.command == PASS"
```

## メモリフォレンジック

### Volatility3
```bash
# プロファイル確認
vol3 -f [dump] windows.info

# プロセス一覧
vol3 -f [dump] windows.pslist
vol3 -f [dump] windows.pstree

# ファイル検索
vol3 -f [dump] windows.filescan | grep -i flag
vol3 -f [dump] windows.filescan | grep -i password

# ファイル抽出
vol3 -f [dump] windows.dumpfiles --physaddr [addr]

# コマンド履歴
vol3 -f [dump] windows.cmdline

# レジストリ
vol3 -f [dump] windows.registry.printkey
```

## ZIP/アーカイブ

```bash
zipinfo [file.zip]
unzip -l [file.zip]

# パスワードクラック
fcrackzip -u -D -p rockyou.txt [file.zip]
john --wordlist=rockyou.txt hash.txt
```

## ディスクイメージ

```bash
fdisk -l [image.dd]
mmls [image.dd]
fls -r [image.dd]
icat [image.dd] [inode] > extracted_file
```
