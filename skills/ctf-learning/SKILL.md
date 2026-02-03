# CTF 継続学習スキル

## 目的
CTFの問題を解くたびに、解法パターンを自動抽出・蓄積し、次回以降の速度を向上させる。
`continuous-learning-v2` の instinct パターンを CTF に特化。

## 学習フロー
1. 問題完了時に `/ctf-flag` が呼ばれる
2. 解法プロセスを分析し、パターンを抽出
3. `patterns/` ディレクトリにカテゴリ別で追記
4. `instincts.json` に信頼度スコア付きで記録

## instincts.json 形式
```json
{
  "instincts": [
    {
      "trigger": "Base64っぽい文字列が問題文にある",
      "action": "まずBase64デコードを試す",
      "category": "crypto",
      "confidence": 0.95,
      "source_count": 12
    },
    {
      "trigger": "PNG画像が添付されている",
      "action": "zsteg → exiftool → binwalk の順で実行",
      "category": "forensics",
      "confidence": 0.88,
      "source_count": 7
    },
    {
      "trigger": "ログインフォームがある",
      "action": "SQLi基本ペイロードを試す",
      "category": "web",
      "confidence": 0.75,
      "source_count": 15
    }
  ]
}
```

## 蓄積ルール
- 同じパターンが繰り返し出現 → confidence を上げる
- 失敗したアプローチも記録（negative pattern）
- コンテストごとの傾向も記録（大会名タグ付き）

## patterns/ ディレクトリ構造
```
patterns/
├── web.md           # Web問題の解法蓄積
├── crypto.md        # 暗号問題の解法蓄積
├── forensics.md     # フォレンジック解法蓄積
├── pwn.md           # Pwn解法蓄積
├── osint.md         # OSINT解法蓄積
└── cyberdefense.md  # 防衛省CTF特有パターン
```

## 自動パターン抽出
問題完了時に以下を記録:
1. 問題の特徴（キーワード、ファイル形式、ヒント）
2. 成功した解法手順
3. 使用したツール
4. かかった時間
5. 失敗したアプローチ（あれば）
