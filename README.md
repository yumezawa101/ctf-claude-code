# CTF Claude Code

**Kali Linux 環境前提**の CTF（Capture The Flag）自動化 Claude Code プラグイン。

## 特徴

- 問題の自動分類・優先順位付け
- カテゴリ別専門エージェント（Web/Crypto/Forensics/Pwn/OSINT）
- フラグ自動検出 Hook
- 解法パターンの継続学習
- Playwright MCP によるブラウザ自動化

---

## 前提条件

| 必須 | バージョン | 確認コマンド |
|------|-----------|-------------|
| Claude Code | 最新版 | `claude --version` |
| Node.js | 18以上 | `node --version` |
| Kali Linux | 推奨 | `uname -a` |

---

## インストール

### 一括インストール（推奨）

```bash
git clone https://github.com/yumezawa101/ctf-claude-code.git
cd ctf-claude-code
./install.sh
```

### Hooks設定（必須）

`~/.claude/settings.json` に以下を追加：

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
        ]
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
        ]
      }
    ]
  }
}
```

### 導入確認

```bash
ls ~/.claude/agents/ctf-*.md
ls ~/.claude/commands/ctf-*.md
claude --context ctf
```

---

## 利用フロー

### どのフローを選ぶ？

```
┌─────────────────────────────────────────────────────────┐
│  CTF開始                                                 │
│    ↓                                                    │
│  問題数は？                                              │
│    ├── 1-3問 → 基本フロー（手動）                        │
│    ├── 4問以上 → 並列フロー（/ctf-batch）                │
│    └── 全自動したい → 完全自動化（/ctf-auto）            │
└─────────────────────────────────────────────────────────┘
```

### 基本フロー（1問ずつ手動）

```bash
claude --context ctf      # 1. CTFモードで起動
/ctf-start                # 2. セッション開始
/ctf-recon <URL>          # 3. 偵察（オプション）
/ctf-solve "問題名"       # 4. 問題解析
/ctf-hint "特徴"          # 5. ヒント取得（行き詰まった時）
/ctf-flag FLAG{...}       # 6. フラグ記録
```

### 並列フロー（複数問題を同時処理）

```bash
# 1. problems.json を作成
# 2. 並列実行
./scripts/ctf-parallel.sh problems.json 5
```

### 完全自動化フロー（取得→解析→提出）

```bash
# 1. プラットフォーム設定
cp templates/platform-ctfd.json .ctf/platform.json

# 2. 完全自動実行
/ctf-auto https://ctf.example.com --submit
```

---

## コマンド一覧

| コマンド | 機能 | 使用例 |
|----------|------|--------|
| `/ctf-start` | セッション開始 | `/ctf-start` |
| `/ctf-solve` | 問題解析 | `/ctf-solve "Login Bypass"` |
| `/ctf-recon` | 初手偵察 | `/ctf-recon http://target.com` |
| `/ctf-flag` | フラグ記録 | `/ctf-flag FLAG{example}` |
| `/ctf-hint` | ヒント取得 | `/ctf-hint "PNG画像"` |
| `/ctf-batch` | 並列実行 | `/ctf-batch problems.json` |
| `/ctf-auto` | 完全自動化 | `/ctf-auto <URL> --submit` |

---

## エージェント一覧

| エージェント | 用途 | 対応する問題例 |
|-------------|------|---------------|
| ctf-orchestrator | 問題振り分け・進捗管理 | 全般 |
| ctf-web | Web脆弱性 | SQLi, XSS, LFI, SSRF |
| ctf-crypto | 暗号解読 | RSA, XOR, AES, Base64 |
| ctf-forensics | フォレンジック | ステガノ, PCAP, メモリダンプ |
| ctf-pwn | バイナリ解析 | BOF, ROP, Format String |
| ctf-osint | 公開情報調査 | 画像調査, Google Dorking |
| ctf-scraper | プラットフォーム操作 | CTFd, rCTF |

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

## 並列実行（大量問題を高速処理）

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
./scripts/ctf-parallel.sh problems.json 5
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

| カテゴリ | ツール |
|---------|--------|
| 情報収集 | nmap, nikto, whatweb, gobuster, ffuf |
| Web | sqlmap, burpsuite, hydra |
| Forensics | binwalk, exiftool, volatility3, wireshark |
| Pwn | gdb, pwndbg, ghidra, radare2, pwntools |
| Crypto | python3, pycryptodome, sage |

---

## ディレクトリ構成と役割

### 各ディレクトリの役割

| ディレクトリ | 役割 | いつ使われるか | どう使うか |
|-------------|------|---------------|-----------|
| **contexts/** | セッションの振る舞いを定義 | `--context ctf` で起動時 | そのまま使う / 行動原則を編集 |
| **commands/** | スラッシュコマンドの処理手順 | `/ctf-solve` など呼び出し時 | そのまま使う / 新コマンド追加可 |
| **agents/** | 専門エージェントの定義 | Claudeがサブタスクを委譲時 | そのまま使う / エージェント追加可 |
| **skills/** | 知識ベース・パターン集 | Claudeが参照情報として読む | **Writeup追加で学習強化** |
| **rules/** | 常に従うべきルール | 全セッションで常時適用 | タイムアウト時間など編集可 |
| **hooks/** | ツール実行時の自動処理 | Bash実行後、セッション終了時 | settings.jsonに設定が必要 |
| **templates/** | コードテンプレート | 問題解析時にコピーして使用 | 自分用テンプレート追加可 |
| **scripts/** | 自動化スクリプト | 並列実行、自動解析など | シェルから直接実行 |
| **mcp-configs/** | MCP（外部ツール）設定 | ブラウザ自動化など | ~/.claudeにコピーして使用 |
| **.ctf/** | 進捗管理データ | セッション中に読み書き | **自動更新**（編集不要） |

### カスタマイズのポイント

| やりたいこと | 編集するファイル |
|-------------|-----------------|
| 行動原則を変えたい | `contexts/ctf.md` |
| タイムアウト時間を変えたい | `rules/ctf.md` |
| 過去の解法を学習させたい | `skills/ctf-learning/patterns/*.md` |
| 新しいコマンドを追加したい | `commands/` に `.md` ファイル追加 |
| フラグ形式を追加したい | `scripts/hooks/ctf-flag-detect.js` |

### ファイル構成

```
ctf-claude-code/
|-- install.sh           # 一括インストールスクリプト
|-- contexts/            # セッションモード定義
|   |-- ctf.md           # CTFモード（行動原則、禁止事項）
|-- commands/            # スラッシュコマンド
|   |-- ctf-start.md     # /ctf-start
|   |-- ctf-solve.md     # /ctf-solve
|   |-- ctf-hint.md      # /ctf-hint
|   |-- ...
|-- agents/              # 専門エージェント
|   |-- ctf-orchestrator.md  # 問題振り分け
|   |-- ctf-web.md       # Web問題
|   |-- ctf-crypto.md    # 暗号問題
|   |-- ...
|-- skills/              # 知識・学習データ
|   |-- ctf-knowledge/   # カテゴリ別解法パターン
|   |-- ctf-learning/    # 継続学習・instincts
|-- rules/               # 常時適用ルール
|   |-- ctf.md           # 10分ルールなど
|-- hooks/               # Hook設定
|-- scripts/             # 自動化スクリプト
|-- templates/           # ソルバーテンプレート
|-- mcp-configs/         # MCP設定（Playwright等）
|-- .ctf/                # 進捗管理
```

---

## 手動インストール（詳細）

一括インストールではなく手動で設定したい場合：

### 1. ディレクトリ準備

```bash
mkdir -p ~/.claude/{agents,commands,rules,contexts,skills,scripts/hooks}
```

### 2. ファイルコピー

```bash
cp agents/*.md ~/.claude/agents/
cp commands/*.md ~/.claude/commands/
cp rules/*.md ~/.claude/rules/
cp contexts/*.md ~/.claude/contexts/
cp -r skills/* ~/.claude/skills/
cp scripts/hooks/*.js ~/.claude/scripts/hooks/
cp -r templates ~/.claude/
```

### 3. MCP設定（ブラウザ自動化が必要な場合）

```bash
cp mcp-configs/mcp-servers.json ~/.claude/
npm install -g @anthropic-ai/mcp-playwright
npx playwright install chromium
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
