# CTF ドメイン知識

## カテゴリ別解法データベース

このskillはCTF問題の解法パターンを体系的に格納する。
各カテゴリのサブファイルに詳細なパターン・コマンド・テンプレートを記載。

### 参照ファイル
- `web-patterns.md` - Web脆弱性パターン集
- `crypto-patterns.md` - 暗号解法パターン集
- `forensics-patterns.md` - フォレンジック解法パターン集
- `pwn-patterns.md` - バイナリ解法パターン集
- `osint-patterns.md` - OSINT手法集

## クイックリファレンス

### 必須ツール
| カテゴリ | ツール |
|----------|--------|
| 共通 | curl, strings, file, xxd |
| Web | sqlmap, gobuster, ffuf, burpsuite |
| Crypto | python3, pycryptodome, sage |
| Forensics | binwalk, exiftool, volatility3, wireshark |
| Pwn | gdb, pwntools, checksec, ROPgadget |
| OSINT | sherlock, exiftool |

### オンラインリソース
- CyberChef: https://gchq.github.io/CyberChef/
- FactorDB: http://factordb.com/
- GTFOBins: https://gtfobins.github.io/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.xyz/
- CrackStation: https://crackstation.net/

### エンコーディング早見表
| 特徴 | 形式 |
|------|------|
| `=`終端, A-Za-z0-9+/ | Base64 |
| A-Z2-7, `=`終端 | Base32 |
| 0-9a-f のみ | Hex |
| 32文字 | MD5 |
| 40文字 | SHA1 |
| 64文字 | SHA256 |
