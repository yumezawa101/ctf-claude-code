# /ctf-batch - 並列バッチ実行

複数の問題を並列で自動解析するためのセットアップ。

## 使用法

```
/ctf-batch [problems.json]
```

## 実行フロー

### 1. 問題ファイルの準備

`problems.json` を作成:

```json
{
  "contest": "CyberDefense 2025",
  "problems": [
    {"name": "SQLi Basic", "category": "web", "points": 100, "url": "http://..."},
    {"name": "RSA Easy", "category": "crypto", "points": 100, "file": "rsa.txt"},
    {"name": "Hidden Flag", "category": "forensics", "points": 150, "file": "image.png"}
  ]
}
```

### 2. 並列実行スクリプトを起動

```bash
chmod +x scripts/ctf-parallel.sh
./scripts/ctf-parallel.sh problems.json 5
```

### 3. tmuxで監視

```bash
tmux attach -t ctf-parallel
# Ctrl+B, n で次のウィンドウ
# Ctrl+B, p で前のウィンドウ
# Ctrl+B, d でデタッチ
```

## カテゴリ別分散

スクリプトは自動でカテゴリ別に分類:

| ウィンドウ | カテゴリ | 担当エージェント |
|-----------|---------|----------------|
| 0 | web | ctf-web |
| 1 | crypto | ctf-crypto |
| 2 | forensics | ctf-forensics |
| 3 | pwn | ctf-pwn |
| 4 | osint | ctf-osint |

## 手動並列実行

tmuxなしの場合、複数ターミナルで:

```bash
# ターミナル1
claude --context ctf -p "Web問題を解いて: Login Bypass, XSS Challenge, SSRF"

# ターミナル2
claude --context ctf -p "Crypto問題を解いて: RSA Easy, XOR Cipher, Base64 Hell"

# ターミナル3
claude --context ctf -p "Forensics問題を解いて: Hidden Flag, Memory Dump, PCAP Analysis"
```

## 結果確認

```bash
# 進捗確認
cat .ctf/progress.json | jq '.problems[] | select(.status == "solved")'

# フラグ一覧
grep -r "FLAG{" .ctf/
```

## 推奨設定

- **並列数**: 3-5（API制限とPC負荷を考慮）
- **タイムアウト**: 問題あたり3-5分
- **優先順位**: 低配点から着手
