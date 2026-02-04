---
name: ctf-scraper
description: CTFプラットフォームから問題を自動取得するエージェント
tools: ["Bash", "Read", "Write", "mcp__playwright__*"]
model: opus
---

# CTF Problem Scraper

Playwright MCPを使用してCTFプラットフォームから問題を自動取得。

## 対応プラットフォーム

### CTFd (最も一般的)
```javascript
// セレクタ
{
  "challengeList": ".challenge-button, .card-link",
  "challengeModal": "#challenge-window",
  "title": ".challenge-name, .card-title",
  "category": ".challenge-category, .card-text",
  "points": ".challenge-points, .badge",
  "description": ".challenge-description, .card-body",
  "files": ".challenge-files a",
  "flagInput": "#submission-input, input[name='flag']",
  "submitBtn": "#submit-key, button[type='submit']"
}
```

### rCTF
```javascript
{
  "challengeList": ".chall",
  "title": ".chall-name",
  "category": ".chall-category",
  "points": ".chall-points"
}
```

## 実行手順

### 1. ログイン

```
Playwright MCP を使用:
1. navigate: CTFのURLへアクセス
2. screenshot: ログインページ確認
3. fill: ユーザー名入力
4. fill: パスワード入力
5. click: ログインボタン
6. screenshot: ログイン成功確認
```

### 2. 問題一覧取得

```
1. navigate: /challenges へ移動
2. wait: 問題一覧の読み込み完了を待機
3. evaluate: DOM から問題情報を抽出
   - 問題名
   - カテゴリ
   - 配点
   - 解答済みフラグ
4. 各問題をクリックして詳細取得
```

### 3. 問題詳細取得

```
各問題について:
1. click: 問題カードをクリック
2. wait: モーダル/詳細ページの表示
3. evaluate: 問題文を抽出
4. evaluate: 添付ファイルのURLを抽出
5. ファイルダウンロード
6. close: モーダルを閉じる
```

### 4. ファイルダウンロード

```bash
# 添付ファイルをダウンロード
mkdir -p .ctf/files/{problem_name}
wget -P .ctf/files/{problem_name}/ {file_url}
```

### 5. 結果保存

```json
// .ctf/problems.json
{
  "platform": "ctfd",
  "url": "https://ctf.example.com",
  "fetchedAt": "2025-01-01T12:00:00Z",
  "problems": [
    {
      "id": 1,
      "name": "Login Bypass",
      "category": "web",
      "points": 100,
      "description": "SQLインジェクションでログインをバイパスせよ",
      "files": [".ctf/files/login-bypass/app.py"],
      "url": "http://challenge.ctf.example.com:8080",
      "solved": false
    }
  ]
}
```

## フラグ提出

```
1. navigate: 問題ページへ
2. fill: フラグ入力欄にフラグを入力
3. click: 提出ボタン
4. wait: 結果表示
5. evaluate: 正誤判定を取得
6. screenshot: 結果を保存
```

## 使用例

```
/ctf-scraper https://ctf.example.com --user admin --pass password

→ .ctf/problems.json が生成される
→ 添付ファイルは .ctf/files/ に保存
```

## エラーハンドリング

- ログイン失敗: 認証情報を確認
- タイムアウト: ネットワーク/サーバー状態を確認
- セレクタ不一致: プラットフォーム種類を確認
- CAPTCHA: 手動介入が必要
