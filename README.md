# CTF Claude Code

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Kali Linux 環境前提**の CTF（Capture The Flag）自動化 Claude Code プラグイン。

---

## 特徴

- 問題の自動分類・優先順位付け
- カテゴリ別専門エージェント（Web/Crypto/Forensics/Pwn/OSINT）
- フラグ自動検出 Hook
- 解法パターンの継続学習
- Playwright MCP によるブラウザ自動化

---

## クイックスタート

```bash
# CTFモードで起動
claude --context ctf

# セッション開始
> /ctf-start

# 問題を解く
> /ctf-solve "Login Bypass"

# フラグを記録
> /ctf-flag FLAG{example}
```

---

## ディレクトリ構成

```
ctf-claude-code/
|-- agents/              # CTF専門エージェント
|   |-- ctf-orchestrator.md  # 問題振り分け・進捗管理
|   |-- ctf-web.md           # Web問題専門
|   |-- ctf-crypto.md        # 暗号問題専門
|   |-- ctf-forensics.md     # フォレンジック専門
|   |-- ctf-pwn.md           # Pwn/Reversing専門
|   |-- ctf-osint.md         # OSINT専門
|
|-- commands/            # スラッシュコマンド
|   |-- ctf-start.md         # /ctf-start - セッション開始
|   |-- ctf-solve.md         # /ctf-solve - 問題解析
|   |-- ctf-recon.md         # /ctf-recon - 初手偵察
|   |-- ctf-flag.md          # /ctf-flag - フラグ記録
|   |-- ctf-batch.md         # /ctf-batch - 並列バッチ実行
|
|-- skills/              # 知識・学習
|   |-- ctf-knowledge/       # カテゴリ別解法パターン
|   |-- ctf-learning/        # 継続学習・instincts
|       |-- instincts.json   # 学習済みパターン
|       |-- patterns/        # 大会別解法メモ
|
|-- rules/               # ルール
|   |-- ctf.md               # CTFルール（3分ルール等）
|
|-- contexts/            # コンテキスト
|   |-- ctf.md               # CTFモード設定
|
|-- hooks/               # Hook
|   |-- hooks.json           # フラグ自動検出等
|
|-- scripts/             # スクリプト
|   |-- ctf-parallel.sh      # 並列実行スクリプト
|   |-- hooks/               # Hook実装
|       |-- ctf-flag-detect.js
|       |-- ctf-session-save.js
|
|-- templates/           # テンプレート
|   |-- pwn-template.py      # pwntools テンプレート
|   |-- crypto-template.py   # 暗号解法テンプレート
|   |-- web-template.py      # Web攻撃テンプレート
|   |-- forensics-template.sh # フォレンジック初手
|
|-- mcp-configs/         # MCP設定
|   |-- mcp-servers.json     # Playwright等
|
|-- .ctf/                # 進捗管理
|   |-- progress.json        # 問題ステータス
```

---

## エージェント

| エージェント | 用途 |
|-------------|------|
| ctf-orchestrator | 問題振り分け・進捗管理 |
| ctf-web | SQLi, XSS, LFI, SSRF 等 |
| ctf-crypto | RSA, XOR, エンコード |
| ctf-forensics | ステガノ, メモリダンプ, PCAP |
| ctf-pwn | BOF, ROP, フォーマット文字列 |
| ctf-osint | 画像調査, Google Dorking |

---

## コマンド

| コマンド | 機能 |
|----------|------|
| `/ctf-start` | セッション開始、問題一覧取得 |
| `/ctf-solve` | 専門エージェントで問題解析 |
| `/ctf-recon` | 初手偵察を自動実行 |
| `/ctf-flag` | フラグ検証・記録 |
| `/ctf-batch` | 並列バッチ実行セットアップ |
| `/ctf-auto` | 完全自動（取得→解析→提出） |

---

## 完全自動化（25問自動取得＆自動回答）

```
┌──────────────────────────────────────────────────────┐
│ 1. 問題自動取得 (Playwright MCP)                      │
│    CTFプラットフォームにログイン→問題スクレイピング    │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ 2. 分類・優先順位付け                                 │
│    カテゴリ判定 → 配点順ソート → 並列グループ分け      │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ 3. 10並列解析                                         │
│    Web | Crypto | Forensics | Pwn | OSINT × 2        │
│    各10分で自動スキップ                               │
└──────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│ 4. フラグ自動提出                                     │
│    Playwrightで入力→送信→結果確認                    │
└──────────────────────────────────────────────────────┘
```

### 使用法

```bash
# 1. プラットフォーム設定
cp templates/platform-ctfd.json .ctf/platform.json
# 認証情報を編集

# 2. 完全自動実行
/ctf-auto https://ctf.example.com --submit

# 3. 結果確認
cat .ctf/progress.json
```

---

## 並列実行（25問を高速処理）

カテゴリ別に10並列で実行し、大量の問題を短時間で処理。

### 1. 問題ファイル作成

```json
{
  "contest": "CTF大会名",
  "problems": [
    {"name": "Login Bypass", "category": "web", "points": 100},
    {"name": "RSA Easy", "category": "crypto", "points": 100},
    {"name": "Hidden Flag", "category": "forensics", "points": 150}
  ]
}
```

### 2. 並列実行

```bash
# スクリプトで自動分散
./scripts/ctf-parallel.sh problems.json 5

# tmuxセッションで監視
tmux attach -t ctf-parallel
```

### 3. 手動並列（tmuxなし）

```bash
# ターミナル1: Web
claude --context ctf -p "Web問題を解いて: Login Bypass, XSS, SSRF"

# ターミナル2: Crypto
claude --context ctf -p "Crypto問題を解いて: RSA Easy, XOR, AES"

# ターミナル3: Forensics
claude --context ctf -p "Forensics問題を解いて: Stego, PCAP, Memory"
```

---

## 必須ツール（Kali Linux標準）

```bash
# 情報収集
nmap, nikto, whatweb, gobuster, ffuf

# Web
sqlmap, burpsuite, hydra

# Forensics
binwalk, exiftool, volatility3, wireshark

# Pwn
gdb, pwndbg, ghidra, radare2, pwntools

# Crypto
python3, pycryptodome, sage
```

---

## インストール

```bash
# リポジトリをクローン
git clone <repository-url>
cd ctf-claude-code

# Claude設定にコピー
cp agents/*.md ~/.claude/agents/
cp commands/*.md ~/.claude/commands/
cp rules/*.md ~/.claude/rules/
cp contexts/*.md ~/.claude/contexts/
cp -r skills/* ~/.claude/skills/

# Hook設定を ~/.claude/settings.json に追加
# hooks/hooks.json の内容を参照
```

---

## 過去の解法を学習させる

`skills/ctf-learning/patterns/` に大会ごとのWriteupを追加：

```markdown
# 大会名 20XX

## 問題名（カテゴリ/配点）
**パターン**: SQLi blind
**解法**: time-based injection
**ペイロード**: `' AND SLEEP(5)--`
**学び**: WAFバイパスには大文字小文字混在が有効
```

`skills/ctf-learning/instincts.json` に自動学習されたパターンが蓄積されます。

---

## ライセンス

MIT
