# CTF ルール

## 環境
**Kali Linux** を使用。主要ツールは標準インストール済み。
ワードリスト: `/usr/share/wordlists/` (rockyou.txt, seclists等)

## ディレクトリ構造

```
./ctf_workspace/              # 作業ディレクトリ
├── config.json               # プラットフォーム設定
├── problems.json             # 問題データ
├── progress.json             # 進捗管理
├── solutions/                # カテゴリ別 > 問題別
│   ├── web/
│   │   └── problem_name/     # 問題ごとにディレクトリ
│   ├── crypto/
│   ├── forensics/
│   ├── pwn/
│   └── osint/
├── files/                    # 添付ファイル
└── screenshots/              # スクリーンショット
```

## 速度優先
- 簡単な問題（低配点）から着手する
- 1問5分で進展なければスキップまたはエスカレート
- 過度な検証より実行速度を優先
- 完璧なExploitより動くExploitを優先

## 5分ルール強制（重要）

### タイムアウト動作
```
開始 → 4分経過 → 警告「残り1分」 → 5分経過 → 強制終了
```

### 4分経過時
- 現在の進捗を評価
- 進展あり → 継続（最大+2分延長可）
- 進展なし → 現状を保存して終了準備

### 5分経過時（強制）
- 即座に現在の状態を保存
- `status: "timeout"` に更新
- 次の問題へ進む（待機しない）

### ツールビルドの禁止
- `make`, `cmake`, `cargo build` 等の長時間ビルドは避ける
- 代替手法を優先:
  - apt/pip でインストール済みのツールを使う
  - Pythonスクリプトで代用
  - オンラインツール（CyberChef等）を活用
- ビルドが必須の場合 → スキップして次へ

## モデル選択
| タスク | 推奨モデル | 理由 |
|--------|-----------|------|
| 問題分類・初手偵察 | Sonnet | コスト効率 |
| 複雑な推論・暗号解読 | Opus | 高度な推論能力 |
| Exploit作成 | Opus | 正確性重視 |
| コード生成 | Opus | 品質重視 |

## 自動化原則
- 手動で繰り返す作業は即スクリプト化
- フラグ検出はHookで自動化済み
- ブラウザ操作はPlaywright MCPで自動化
- 初手チェックリストは必ず全実行

## カテゴリ別初手

### Web
1. curl -v でヘッダー確認
2. robots.txt, .git/HEAD チェック
3. ソースコードでflag/hint検索
4. ディレクトリ列挙

### Crypto
1. エンコーディング判定
2. RSAパラメータ確認
3. 文字頻度分析

### Forensics
1. file コマンド
2. strings | grep flag
3. exiftool
4. binwalk -e

### Pwn
1. checksec
2. file
3. strings | grep flag
4. 実行して挙動確認

### OSINT
1. EXIF情報確認
2. 逆画像検索
3. Google Dorking

## セキュリティ
- CTF環境外への攻撃は絶対禁止
- 取得したフラグ・解法は外部公開しない（大会規約準拠）
- 他チームへの妨害行為禁止

## 進捗管理
- `ctf_workspace/progress.json` で全問題を追跡
- 状態: 🔴未着手 / 🟡進行中 / 🟢完了 / ⏭️スキップ / ⏱️タイムアウト
- 解法は `skills/ctf-learning/patterns/` に蓄積

## 並列処理の原則
- 完了したエージェントは他を待たず次の問題へ
- バッチ単位で待機しない（キューベース処理）
- 同時実行数は `config/settings.json` で管理
