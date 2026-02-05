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
│    └── 4問以上 → 自動化フロー（/ctf-auto）               │
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

### 自動化フロー（/ctf-auto）

```bash
/ctf-auto   # 対話形式で設定を入力
```

対話で聞かれる項目:
- URL（空欄でproblems.json使用）
- ログイン情報（URL指定時）
- カテゴリ絞り込み
- 解きたい問題
- 配点フィルタ
- 自動提出するか

---

## コマンド詳細

### `/ctf-start` - セッション開始

CTFセッションを開始し、進捗管理ファイルを初期化します。

```bash
/ctf-start [コンテスト名]
```

**実行内容:**
1. `.ctf/progress.json` を作成
2. 問題一覧を取得・分類
3. 優先順位を決定（低配点→高配点）

**生成ファイル:**
```json
// .ctf/progress.json
{
  "contest": "コンテスト名",
  "started_at": "2025-01-01T00:00:00Z",
  "problems": [
    {
      "name": "問題名",
      "category": "Web",
      "points": 100,
      "status": "pending",
      "flag": null
    }
  ]
}
```

---

### `/ctf-solve` - 問題解決

指定した問題をカテゴリに応じた専門エージェントで解きます。

```bash
/ctf-solve [問題名 or ID]
/ctf-solve "Login Bypass"
/ctf-solve 3
```

**実行内容:**
1. 問題のカテゴリを判定
2. 専門エージェントを起動
3. 5分ルール: 進展なければスキップ提案
4. フラグ取得時は `progress.json` を更新

**エージェント振り分け:**

| カテゴリ | エージェント |
|----------|-------------|
| Web | ctf-web |
| Crypto | ctf-crypto |
| Forensics | ctf-forensics |
| Pwn | ctf-pwn |
| OSINT | ctf-osint |
| Misc | ctf-orchestrator |

---

### `/ctf-recon` - 初期偵察

URLまたはファイルに対して初手偵察を自動実行します。

```bash
/ctf-recon <URL or ファイルパス>
/ctf-recon https://target.ctf/challenge
/ctf-recon ./challenge.png
```

**URL指定時の実行内容:**
```bash
curl -v [URL]                    # 基本情報
curl -s [URL]/robots.txt         # 隠しファイル
curl -s [URL]/.git/HEAD          # Git漏洩チェック
curl -I [URL]                    # ヘッダー確認
```

**ファイル指定時の実行内容:**
```bash
file [filename]                  # ファイル種別
strings [filename] | grep -i flag  # 文字列検索
exiftool [filename]              # メタデータ
binwalk -e [filename]            # 埋め込みファイル
```

**出力:**
- 発見した情報のサマリー
- 推奨する攻撃ベクトル
- 次のステップ提案

---

### `/ctf-flag` - フラグ記録

フラグを検証し、進捗ファイルに記録します。

```bash
/ctf-flag FLAG{example_flag}
/ctf-flag [問題名] FLAG{...}
```

**実行内容:**
1. フラグ形式を検証
2. `progress.json` を更新
3. 解法パターンを学習データに追記

**対応フラグ形式:**
```
FLAG{...}
flag{...}
ctf{...}
SECCON{...}
picoCTF{...}
[大会名]{...}
```

**記録内容:**
```json
{
  "flag": "FLAG{...}",
  "solved_at": "2025-01-01T00:05:00Z",
  "method": "SQLi in login form",
  "tools_used": ["sqlmap", "curl"]
}
```

---

### `/ctf-hint` - ヒント取得

問題の特徴からマッチするヒントを学習データベースから検索します。

```bash
/ctf-hint <問題の特徴>
/ctf-hint --category <カテゴリ>
/ctf-hint --list
```

**使用例:**
```bash
/ctf-hint "ログインフォームがある"
# → SQLi基本ペイロード（' OR 1=1--）を試す

/ctf-hint "PNG画像"
# → zsteg → exiftool → binwalk の順で実行

/ctf-hint "n, e, c パラメータ"
# → RSA問題。nをfactordbで素因数分解

/ctf-hint --category crypto
# → 暗号カテゴリのヒント一覧
```

**クイックリファレンス:**

| 特徴 | ヒント |
|------|--------|
| Base64文字列 | Base64デコードを試す |
| PNG画像 | `zsteg` → `exiftool` → `binwalk` |
| JPG画像 | `steghide`（パスワード空）→ `exiftool` |
| ログインフォーム | SQLi基本ペイロード |
| n, e, c パラメータ | RSA、factordbで素因数分解 |
| pcapファイル | `tshark`/`wireshark`でHTTP確認 |
| ELFバイナリ | `checksec` → `file` → `strings` |

**オンラインリソース:**
- CyberChef: https://gchq.github.io/CyberChef/
- FactorDB: http://factordb.com/
- CrackStation: https://crackstation.net/
- HackTricks: https://book.hacktricks.xyz/

---

### `/ctf-auto` - 対話式自動化

対話形式で設定を入力し、問題を自動解析します。

```bash
/ctf-auto
```

**対話フロー:**
```
┌─────────────────────────────────────────────────────────┐
│ CTF Auto Solver - 設定                                   │
├─────────────────────────────────────────────────────────┤
│ [1] URL: (空欄でproblems.json使用)                       │
│ [2] ユーザー名: (URL指定時のみ)                          │
│ [3] パスワード: (URL指定時のみ)                          │
│ [4] カテゴリ: web,crypto (空欄で全て)                    │
│ [5] 問題: Login Bypass (空欄で全て)                      │
│ [6] 配点: 最小100, 最大300 (空欄で制限なし)              │
│ [7] 自動提出: y/N                                        │
└─────────────────────────────────────────────────────────┘
```

**設定項目:**

| 項目 | 説明 | デフォルト |
|------|------|-----------|
| URL | CTFプラットフォームURL | problems.json使用 |
| ユーザー名 | ログイン用 | - |
| パスワード | ログイン用 | - |
| カテゴリ | カンマ区切りで絞り込み | 全て |
| 問題名 | カンマ区切りで指定 | 全て |
| 配点フィルタ | 最小/最大 | 0〜∞ |
| 自動提出 | フラグを自動submit | No |

**使用例:**
```bash
# 全自動（URL指定）
/ctf-auto
> URL: https://ctf.example.com
> ユーザー名: myteam
> パスワード: ****
> カテゴリ: (空欄)
> 自動提出: y

# 特定カテゴリのみ
/ctf-auto
> URL: (空欄)
> カテゴリ: web,crypto
> 自動提出: n

# 結果確認
cat .ctf/progress.json
```

---

## コマンド一覧（クイックリファレンス）

| コマンド | 機能 | 使用例 |
|----------|------|--------|
| `/ctf-start` | セッション開始 | `/ctf-start "SECCON 2025"` |
| `/ctf-solve` | 問題解析 | `/ctf-solve "Login Bypass"` |
| `/ctf-recon` | 初手偵察 | `/ctf-recon http://target.com` |
| `/ctf-flag` | フラグ記録 | `/ctf-flag FLAG{example}` |
| `/ctf-hint` | ヒント取得 | `/ctf-hint "PNG画像"` |
| `/ctf-auto` | 対話式自動化 | `/ctf-auto` |

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
| ctf-writeup-generator | Writeup自動生成 | 全カテゴリ |

---

## Writeup自動生成

問題を解決すると、Writeupが自動的に生成されます。

### 生成タイミング

各専門エージェント（ctf-web, ctf-crypto, ctf-forensics, ctf-pwn, ctf-osint）がフラグを取得した後、`ctf-writeup-generator` を呼び出してWriteupを生成します。

### 保存先

```
writeups/
└── [contest-name]/
    ├── problem1.md
    ├── problem2.md
    └── ...
```

### Writeup構成

| セクション | 内容 |
|-----------|------|
| タイトル | 問題名 — Writeup |
| コラム | 問題に関連する豆知識 |
| 問題の概要 | 2〜3行の要約 |
| キーワード・前提知識 | 用語解説（初心者向け） |
| 解法ステップ | [Step N] 形式、コマンド付き |
| Flag | フラグ＋和訳・意図 |
| 防衛者の視点 | 3つ以上の対策 |
| 学び・ポイント | 学んだことのまとめ |
| 難易度評価 | Easy/Medium/Hard |

### サンプル

`writeups/ctf-training-set/base64-decode.md` を参照してください。

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

| ディレクトリ | 役割 | いつ使われるか |
|-------------|------|---------------|
| **contexts/** | セッションの振る舞いを定義 | `--context ctf` で起動時 |
| **commands/** | スラッシュコマンドの処理手順 | `/ctf-solve` など呼び出し時 |
| **agents/** | 専門エージェントの定義 | Claudeがサブタスクを委譲時 |
| **skills/** | 知識ベース・パターン集 | Claudeが参照情報として読む |
| **rules/** | 常に従うべきルール | 全セッションで常時適用 |
| **hooks/** | ツール実行時の自動処理 | Bash実行後、セッション終了時 |
| **templates/** | コードテンプレート | 問題解析時にコピーして使用 |
| **scripts/** | 自動化スクリプト | 並列実行、自動解析など |
| **mcp-configs/** | MCP（外部ツール）設定 | ブラウザ自動化など |
| **.ctf/** | 進捗管理データ | セッション中に読み書き |

### カスタマイズ例

#### 過去の解法を学習させたい

`skills/ctf-learning/patterns/web.md` にWriteupを追加：

```markdown
## SECCON 2024 - Login Bypass (Web/100)
**パターン**: SQLi (認証バイパス)
**解法**: `' OR '1'='1' --` でログイン突破
**学び**: エラーメッセージが出ない場合はBlind SQLiを試す
```

#### タイムアウト時間を変えたい

`rules/ctf.md` を編集：

```markdown
# 変更前
- 1問5分で進展なければスキップ

# 変更後（3分に短縮）
- 1問3分で進展なければスキップ
```

#### 新しいフラグ形式を追加したい

`scripts/hooks/ctf-flag-detect.js` の `FLAG_PATTERNS` に追加：

```javascript
const FLAG_PATTERNS = [
  // 既存パターン...
  /MYCTF\{[^}]+\}/gi,  // 追加
];
```

#### エージェントのモデルを変更したい

`config/settings.json` を編集：

```json
{
  "models": {
    "default": "opus",
    "agents": {
      "ctf-orchestrator": "opus",
      "ctf-web": "opus",
      "ctf-crypto": "opus",
      "ctf-forensics": "opus",
      "ctf-pwn": "opus",
      "ctf-osint": "sonnet",
      "ctf-scraper": "sonnet"
    }
  }
}
```

変更後、再インストール:

```bash
./install.sh
```

利用可能なモデル:
- `opus` - 最高性能（複雑な推論、Exploit作成向け）
- `sonnet` - 高速・低コスト（分類、偵察向け）

#### 新しいコマンドを追加したい

`commands/ctf-mycommand.md` を作成：

```markdown
---
name: ctf-mycommand
description: 自作コマンドの説明
---

# 処理内容
1. やること1
2. やること2
```

→ `/ctf-mycommand` で呼び出し可能に

### ファイル構成

```
ctf-claude-code/
|-- install.sh           # 一括インストールスクリプト
|-- config/              # 設定ファイル
|   |-- settings.json    # モデル設定、タイムアウト等
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
|   |-- ctf.md           # 5分ルールなど
|-- hooks/               # Hook設定
|-- scripts/             # 自動化スクリプト
|-- templates/           # ソルバーテンプレート
|-- mcp-configs/         # MCP設定（Playwright等）
|-- writeups/            # 自動生成されたWriteup
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

---

## ディレクトリ使い分け

### ctf-claude-code（このリポジトリ）
- **役割**: テンプレート、エージェント定義、スクリプト
- **インストール先**: `~/.claude/` 配下にコピーされる
- **変更タイミング**: 新機能追加、バグ修正時

### ctf_workspace（作業ディレクトリ）
- **役割**: 実際のCTF作業データ
- **含まれるファイル**:
  - `problems.json` - 問題一覧
  - `progress.json` - 進捗管理
  - `flags.json` - 取得したフラグ（実データ）
  - `solutions/` - カテゴリ別の解法ファイル
- **作成タイミング**: `/ctf-start` 実行時

### 学習パターンの保存先

| 種類 | 保存先 | 用途 |
|------|--------|------|
| グローバル | `~/.claude/skills/ctf-learning/` | セッション跨ぎの知見蓄積 |
| プロジェクト別 | `ctf_workspace/learning/` | 大会固有のパターン |

### テンプレートと実データの違い

| ファイル | hooks/flags.json | ctf_workspace/flags.json |
|----------|-----------------|--------------------------|
| 内容 | 空テンプレート | 実際のフラグデータ |
| 用途 | 新規セッション初期化 | 大会中の記録 |
| 編集 | 基本的に不要 | 自動更新される |
