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

### 1. リポジトリのクローン

```bash
git clone https://github.com/yumezawa101/ctf-claude-code.git
cd ctf-claude-code
```

### 2. Claude Code ディレクトリの準備

```bash
# ~/.claude ディレクトリがなければ作成
mkdir -p ~/.claude/{agents,commands,rules,contexts,skills}
```

### 3. Agents（エージェント）の導入

Agents は Claude Code が特定のタスクを処理する専門エージェントです。

```bash
# CTF専門エージェントをコピー
cp agents/ctf-*.md ~/.claude/agents/

# （オプション）汎用エージェントもコピーする場合
cp agents/*.md ~/.claude/agents/
```

**導入されるCTFエージェント:**

| ファイル | 役割 |
|----------|------|
| `ctf-orchestrator.md` | 問題の振り分け・進捗管理 |
| `ctf-web.md` | Web問題（SQLi, XSS, LFI等） |
| `ctf-crypto.md` | 暗号問題（RSA, XOR, AES等） |
| `ctf-forensics.md` | フォレンジック（ステガノ, PCAP等） |
| `ctf-pwn.md` | Pwn/Reversing（BOF, ROP等） |
| `ctf-osint.md` | OSINT（画像調査, Dorking等） |
| `ctf-scraper.md` | CTFプラットフォームスクレイピング |

### 4. Commands（コマンド）の導入

Commands は `/command-name` 形式で呼び出すスラッシュコマンドです。

```bash
# CTFコマンドをコピー
cp commands/ctf-*.md ~/.claude/commands/

# （オプション）汎用コマンドもコピーする場合
cp commands/*.md ~/.claude/commands/
```

### 5. Rules（ルール）と Contexts（コンテキスト）の導入

```bash
# CTFルールをコピー
cp rules/ctf.md ~/.claude/rules/

# CTFコンテキストをコピー
cp contexts/ctf.md ~/.claude/contexts/
```

### 6. Skills（スキル）の導入

Skills は知識ベースと学習パターンを提供します。

```bash
# CTFスキルをコピー
cp -r skills/ctf-knowledge ~/.claude/skills/
cp -r skills/ctf-learning ~/.claude/skills/
```

### 7. Hooks（フック）の導入

Hooks はツール実行時やセッション終了時に自動で処理を行う機能です。

#### 方法A: settings.json に直接追加（推奨）

`~/.claude/settings.json` を編集し、以下の hooks 設定を追加：

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "tool == \"Bash\"",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/scripts/hooks/ctf-flag-detect.js"
          }
        ],
        "description": "CTF: Bash出力にフラグパターンがあれば自動検出"
      }
    ],
    "SessionEnd": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/scripts/hooks/ctf-session-save.js"
          }
        ],
        "description": "CTF: セッション終了時に解法パターンを抽出・保存"
      }
    ]
  }
}
```

#### 方法B: スクリプトをコピーしてパスを調整

```bash
# Hookスクリプトをコピー
mkdir -p ~/.claude/scripts/hooks
cp scripts/hooks/ctf-*.js ~/.claude/scripts/hooks/
```

**Hooks の説明:**

| Hook | トリガー | 機能 |
|------|----------|------|
| `ctf-flag-detect.js` | Bash実行後 | 出力からフラグパターン（`FLAG{...}`等）を自動検出 |
| `ctf-session-save.js` | セッション終了 | 解法パターンを抽出し `instincts.json` に保存 |

### 8. MCP設定（Playwright自動化）

ブラウザ自動化が必要な場合、MCP設定を追加します。

```bash
# MCP設定をコピー
cp mcp-configs/mcp-servers.json ~/.claude/

# Playwrightをインストール
npm install -g @anthropic-ai/mcp-playwright
npx playwright install chromium
```

### 9. テンプレートのコピー（オプション）

```bash
# ソルバーテンプレートをコピー
cp -r templates ~/.claude/
```

---

## 導入確認

```bash
# 設定ファイルの確認
ls ~/.claude/agents/ctf-*.md
ls ~/.claude/commands/ctf-*.md
ls ~/.claude/skills/ctf-*

# CTFモードで起動
claude --context ctf

# コマンド一覧確認
> /help
```

---

## 一括インストールスクリプト

すべてを一括でインストールするには：

```bash
#!/bin/bash
# install.sh

CLAUDE_DIR="$HOME/.claude"
REPO_DIR="$(pwd)"

# ディレクトリ作成
mkdir -p "$CLAUDE_DIR"/{agents,commands,rules,contexts,skills,scripts/hooks}

# コピー
cp "$REPO_DIR"/agents/*.md "$CLAUDE_DIR/agents/"
cp "$REPO_DIR"/commands/*.md "$CLAUDE_DIR/commands/"
cp "$REPO_DIR"/rules/*.md "$CLAUDE_DIR/rules/"
cp "$REPO_DIR"/contexts/*.md "$CLAUDE_DIR/contexts/"
cp -r "$REPO_DIR"/skills/* "$CLAUDE_DIR/skills/"
cp "$REPO_DIR"/scripts/hooks/*.js "$CLAUDE_DIR/scripts/hooks/"
cp -r "$REPO_DIR"/templates "$CLAUDE_DIR/"

echo "インストール完了！"
echo "~/.claude/settings.json に hooks 設定を追加してください"
```

```bash
chmod +x install.sh
./install.sh
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
