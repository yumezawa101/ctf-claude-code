# CTF ルール

## 環境
**Kali Linux** を使用。主要ツールは標準インストール済み。
ワードリスト: `/usr/share/wordlists/` (rockyou.txt, seclists等)

## 速度優先
- 簡単な問題（低配点）から着手する
- 1問10分で進展なければスキップまたはエスカレート
- 過度な検証より実行速度を優先
- 完璧なExploitより動くExploitを優先

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
- `ctf_solutions/progress.json` で全問題を追跡
- 状態: 🔴未着手 / 🟡進行中 / 🟢完了 / ⏭️スキップ
- 解法は `skills/ctf-learning/patterns/` に蓄積
