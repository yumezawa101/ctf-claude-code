# CTF Training Set

CTF練習用20問セット（初級〜中級）

## 問題一覧

| # | 問題名 | カテゴリ | 配点 | 難易度 |
|---|--------|----------|------|--------|
| 1 | Login Bypass | Web | 100 | Easy |
| 2 | Hidden Comment | Web | 100 | Easy |
| 3 | Cookie Monster | Web | 200 | Medium |
| 4 | Path Traversal | Web | 300 | Medium |
| 5 | API Leak | Web | 400 | Hard |
| 6 | Base64 Decode | Crypto | 100 | Easy |
| 7 | Caesar Cipher | Crypto | 150 | Easy |
| 8 | XOR Magic | Crypto | 200 | Medium |
| 9 | RSA Beginner | Crypto | 350 | Hard |
| 10 | Exif Secrets | Forensics | 100 | Easy |
| 11 | Hidden in Plain Sight | Forensics | 150 | Easy |
| 12 | Zip Password | Forensics | 200 | Medium |
| 13 | PCAP Analysis | Forensics | 300 | Hard |
| 14 | Buffer Overflow 101 | Pwn | 200 | Medium |
| 15 | Format String | Pwn | 350 | Hard |
| 16 | Return to Win | Pwn | 500 | Hard |
| 17 | Social Media Hunt | OSINT | 100 | Easy |
| 18 | Image Location | OSINT | 200 | Medium |
| 19 | QR Code Puzzle | Misc | 100 | Easy |
| 20 | Morse Code | Misc | 150 | Easy |

## カテゴリ分布

```
Web:       5問 (25%) ████████████████████████
Crypto:    4問 (20%) ████████████████████
Forensics: 4問 (20%) ████████████████████
Pwn:       3問 (15%) ███████████████
OSINT:     2問 (10%) ██████████
Misc:      2問 (10%) ██████████
```

## 難易度分布

```
Easy:   9問 (45%) █████████████████████████████████████████████
Medium: 6問 (30%) ██████████████████████████████
Hard:   5問 (25%) █████████████████████████
```

## 使い方

### 1. problems.json をコピー

```bash
cp ctf-training-set/problems.json problems.json
```

### 2. /ctf-auto で解く

```bash
/ctf-auto
> URL: (空欄)
> カテゴリ: (空欄 or web,crypto など)
> 自動提出: n
```

### 3. 個別に解く

```bash
/ctf-solve "Login Bypass"
/ctf-solve "Base64 Decode"
```

## フラグ形式

```
FLAG{...}
```

## ディレクトリ構成

```
ctf-training-set/
├── problems.json      # 問題定義ファイル
├── README.md          # このファイル
├── web/               # Web問題
│   ├── login-bypass/
│   ├── hidden-comment/
│   ├── cookie-monster/
│   ├── path-traversal/
│   └── api-leak/
├── crypto/            # 暗号問題
│   ├── base64-decode/
│   ├── caesar-cipher/
│   ├── xor-magic/
│   └── rsa-beginner/
├── forensics/         # フォレンジック問題
│   ├── exif-secrets/
│   ├── hidden-png/
│   ├── zip-password/
│   └── pcap-analysis/
├── pwn/               # バイナリ問題
│   ├── bof-101/
│   ├── format-string/
│   └── ret2win/
├── osint/             # OSINT問題
│   ├── social-media/
│   └── image-location/
└── misc/              # その他
    ├── qr-code/
    └── morse-code/
```

## 注意事項

- 実際のCTFでは、バイナリファイル（画像、PCAP、実行ファイル等）が必要です
- このセットはテンプレートであり、実際のチャレンジファイルは別途作成してください
- フラグは `problems.json` に記載されています（練習時は見ないように！）
