# CTF プロジェクト CLAUDE.md 例

CTF参加時のプロジェクト設定例。

## 基本設定

```bash
# CTFモードで起動
claude --context ctf
```

## コマンド

| コマンド | 機能 |
|----------|------|
| `/ctf-start` | セッション開始、問題一覧取得 |
| `/ctf-solve [問題名]` | 専門エージェントで自動解析 |
| `/ctf-recon [URL/ファイル]` | 初手偵察を自動実行 |
| `/ctf-flag [FLAG]` | フラグ検証・記録 |

## エージェント

| エージェント | 用途 |
|-------------|------|
| ctf-orchestrator | 問題振り分け・進捗管理 |
| ctf-web | SQLi, XSS, LFI, SSRF 等 |
| ctf-crypto | RSA, XOR, エンコード |
| ctf-forensics | ステガノ, メモリダンプ, PCAP |
| ctf-pwn | BOF, ROP, フォーマット文字列 |
| ctf-osint | 画像調査, Google Dorking |

## 環境: Kali Linux

以下のツールは標準でインストール済み:

```bash
# 情報収集
nmap, nikto, whatweb, wfuzz, gobuster, dirb, ffuf
curl, wget, httpie

# Web
sqlmap, burpsuite, zaproxy
xsser, dalfox, commix

# パスワード
john, hashcat, hydra, fcrackzip

# Forensics
binwalk, foremost, volatility3
exiftool, steghide, zsteg, stegseek
wireshark, tshark, tcpdump
autopsy, sleuthkit

# Reversing/Pwn
gdb, gdb-peda, pwndbg
radare2, ghidra
checksec, ROPgadget, one_gadget

# Crypto
python3, pycryptodome, sage

# その他
netcat, socat, pwntools
metasploit, searchsploit
```

## CTFルール

- 簡単な問題（低配点）から着手
- 1問3分で進展なければスキップ
- 過度な検証より実行速度を優先
- CTF環境外への攻撃は絶対禁止
