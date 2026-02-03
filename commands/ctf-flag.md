---
name: ctf-flag
description: フラグを検証し、progress.jsonに記録する
---

# フラグ検証・記録

## 手順
1. フラグ形式を確認
2. Base64/Hexデコードの可能性を確認
3. progress.jsonを更新
4. 解法をメモとして記録

## フラグ形式パターン
```
FLAG{...}
flag{...}
ctf{...}
SECCON{...}
CyberDefense{...}
[大会名]{...}
```

## 使用方法
```
/ctf-flag FLAG{example_flag_here}
/ctf-flag [問題名] FLAG{...}
```

## 検証チェック
- [ ] 形式が正しいか（括弧の対応）
- [ ] 文字化けがないか
- [ ] Base64デコードで別のフラグが出ないか
- [ ] 提出前に再確認

## 記録内容
```json
{
  "problem_id": 1,
  "flag": "FLAG{...}",
  "solved_at": "ISO8601",
  "solve_time_seconds": 180,
  "method": "SQLi in login form",
  "tools_used": ["sqlmap", "curl"],
  "notes": "解法メモ"
}
```

## 学習への反映
解法パターンを `skills/ctf-learning/patterns/` に自動追記
