# /ctf-auto - 完全自動CTFソルバー

問題取得から回答提出まで完全自動化。

## 使用法

```
/ctf-auto [URL] [--submit] [--category カテゴリ]
```

### 問題ソース（優先順位）

1. `.ctf/platform.json` があれば、プラットフォームから自動取得
2. `problems.json` があれば、そこから読み込み
3. URLが指定されていれば、Playwright MCPで取得

## 実行フロー

```
┌─────────────────────────────────────────────────────────┐
│ 1. 問題自動取得 (Playwright MCP)                         │
│    - ログイン                                            │
│    - 問題一覧スクレイピング                               │
│    - 問題詳細・添付ファイル取得                           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 2. 分類・優先順位付け (ctf-orchestrator)                 │
│    - カテゴリ判定 (Web/Crypto/Forensics/Pwn/OSINT)       │
│    - 配点順ソート (低→高)                                │
│    - 並列グループ分け                                    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 3. 並列解析 (10エージェント同時)                         │
│    ┌─────────┬─────────┬─────────┬─────────┬─────────┐  │
│    │ Web×2   │Crypto×2 │Forens×2 │ Pwn×2   │ OSINT×2 │  │
│    │ Agent   │ Agent   │ Agent   │ Agent   │ Agent   │  │
│    └─────────┴─────────┴─────────┴─────────┴─────────┘  │
│    各エージェント: 5分ルールで自動スキップ                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 4. フラグ検証・自動提出 (--submit時)                     │
│    - フラグ形式チェック                                  │
│    - Playwrightで自動入力・送信                          │
│    - 結果確認・記録                                      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5. 結果レポート                                          │
│    - 解決問題一覧                                        │
│    - 未解決問題と理由                                    │
│    - 獲得ポイント                                        │
└─────────────────────────────────────────────────────────┘
```

## 対応プラットフォーム

| プラットフォーム | 自動取得 | 自動提出 |
|-----------------|---------|---------|
| CTFd           | ✓       | ✓       |
| rCTF           | ✓       | ✓       |
| picoCTF        | ✓       | ✓       |
| カスタム        | 要設定   | 要設定   |

## 設定ファイル

`.ctf/platform.json`:

```json
{
  "type": "ctfd",
  "url": "https://ctf.example.com",
  "credentials": {
    "username": "YOUR_USERNAME",
    "password": "YOUR_PASSWORD"
  },
  "selectors": {
    "problemList": ".challenge-button",
    "problemTitle": ".challenge-name",
    "problemCategory": ".challenge-category",
    "problemPoints": ".challenge-points",
    "problemDescription": ".challenge-description",
    "flagInput": "#flag-input",
    "submitButton": "#flag-submit"
  },
  "flagFormat": "FLAG{.*}"
}
```

## 実行例

```bash
# URLから自動取得して実行
/ctf-auto https://ctf.example.com --submit

# problems.json を使って実行（URLなし）
/ctf-auto --submit

# 問題取得のみ（解析・提出なし）
/ctf-auto https://ctf.example.com --fetch-only

# 特定カテゴリのみ
/ctf-auto --category web,crypto --submit
```

## problems.json の形式

URLを使わない場合、`problems.json` を作成：

```json
{
  "contest": "CTF大会名",
  "problems": [
    {"name": "Login Bypass", "category": "web", "points": 100, "url": "http://..."},
    {"name": "RSA Easy", "category": "crypto", "points": 100, "file": "rsa.txt"},
    {"name": "Hidden Flag", "category": "forensics", "points": 150, "file": "image.png"}
  ]
}
```
