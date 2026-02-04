---
name: ctf-solve
description: 指定した問題をカテゴリに応じた専門エージェントで解く
---

# 問題解決パイプライン

## 手順
1. 問題IDまたは名前を受け取る
2. カテゴリに応じた専門エージェントを起動
3. 10分タイマー: 進展なければエスカレートまたはスキップを提案
4. Flag取得時は形式検証→progress.jsonを更新

## 使用方法
```
/ctf-solve [問題名 or ID]
/ctf-solve Web-01
/ctf-solve 3
```

## エージェント振り分け
| カテゴリ | エージェント |
|----------|-------------|
| Web | ctf-web-solver |
| Crypto | ctf-crypto-solver |
| Forensics | ctf-forensics-solver |
| Pwn | ctf-pwn-solver |
| OSINT | ctf-osint-solver |
| Misc | ctf-orchestrator (手動) |

## 10分ルール
- 開始から10分経過で進捗確認
- 手がかりなし → スキップ提案
- 部分的進展 → 継続 or ヒント要求
- 他の問題との並列処理を検討
