# CTF Writeups

このディレクトリには、解決した問題のWriteupが自動生成されます。

## ディレクトリ構造

```
writeups/
├── [contest-name]/
│   ├── [problem-1].md
│   ├── [problem-2].md
│   └── ...
└── README.md
```

## 生成タイミング

各専門エージェント（ctf-web, ctf-crypto, ctf-forensics, ctf-pwn, ctf-osint）が問題を解決した後、`ctf-writeup-generator` エージェントが自動的にWriteupを生成します。

## Writeupの内容

- 問題概要
- 解法手順（再現可能な詳細）
- 使用ツール
- コードスニペット
- 取得したフラグ
- 学びとポイント

## 手動生成

特定の問題のWriteupを再生成したい場合：

```
ctf-writeup-generatorエージェントを呼び出し、
solve_contextを渡してください。
```
