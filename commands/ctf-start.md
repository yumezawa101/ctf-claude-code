---
name: ctf-start
description: CTFセッションを開始し、問題一覧を取得・分類する
---

# CTFセッション開始

## 手順
1. CTFサイトのURLを受け取る
2. 問題一覧をスクレイピングまたは手動入力で取得
3. 各問題をカテゴリ・配点で分類
4. 優先順位を決定（低配点→高配点）
5. 進捗トラッキングファイルを作成

## 進捗ファイル: `ctf_solutions/progress.json`
```json
{
  "contest": "コンテスト名",
  "started_at": "ISO8601",
  "problems": [
    {
      "id": 1,
      "name": "問題名",
      "category": "Web",
      "points": 100,
      "status": "pending",
      "flag": null,
      "started_at": null,
      "solved_at": null,
      "agent": null,
      "notes": ""
    }
  ]
}
```

## 使用方法
```
/ctf-start [コンテスト名]
```

## 初期化コマンド
```bash
mkdir -p .ctf
echo '{"contest":"","started_at":"","problems":[]}' > ctf_solutions/progress.json
```
