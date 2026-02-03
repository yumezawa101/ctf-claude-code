#!/bin/bash
# CTF並列実行スクリプト
# 使用法: ./ctf-parallel.sh problems.json

set -e

PROBLEMS_FILE="${1:-problems.json}"
PARALLEL_COUNT="${2:-10}"
OUTPUT_DIR=".ctf/parallel-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "=== CTF Parallel Solver ==="
echo "問題ファイル: $PROBLEMS_FILE"
echo "並列数: $PARALLEL_COUNT"
echo "出力先: $OUTPUT_DIR"
echo ""

# 問題ファイルの存在確認
if [ ! -f "$PROBLEMS_FILE" ]; then
    echo "問題ファイルが見つかりません: $PROBLEMS_FILE"
    echo ""
    echo "problems.json の形式:"
    cat << 'EXAMPLE'
{
  "problems": [
    {"name": "Login Bypass", "category": "web", "points": 100, "url": "http://..."},
    {"name": "RSA Easy", "category": "crypto", "points": 150},
    {"name": "Hidden Flag", "category": "forensics", "points": 200, "file": "image.png"}
  ]
}
EXAMPLE
    exit 1
fi

# カテゴリ別に分類
echo "問題をカテゴリ別に分類中..."

# jqがない場合はpythonで代替
if command -v jq &> /dev/null; then
    for category in web crypto forensics pwn osint misc; do
        jq -r ".problems[] | select(.category == \"$category\") | .name" "$PROBLEMS_FILE" 2>/dev/null > "$OUTPUT_DIR/$category.txt" || true
    done
else
    python3 << PYTHON
import json
import os

with open("$PROBLEMS_FILE") as f:
    data = json.load(f)

categories = {}
for p in data.get("problems", []):
    cat = p.get("category", "misc")
    if cat not in categories:
        categories[cat] = []
    categories[cat].append(p["name"])

for cat, names in categories.items():
    with open("$OUTPUT_DIR/" + cat + ".txt", "w") as f:
        f.write("\n".join(names))
PYTHON
fi

echo ""
echo "=== 並列実行開始 ==="
echo ""

# 各カテゴリをtmuxで並列実行
if command -v tmux &> /dev/null; then
    SESSION="ctf-parallel"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    tmux new-session -d -s "$SESSION" -n "main"

    window=0
    for category_file in "$OUTPUT_DIR"/*.txt; do
        [ -s "$category_file" ] || continue
        category=$(basename "$category_file" .txt)
        problems=$(cat "$category_file" | tr '\n' ',' | sed 's/,$//')

        if [ $window -eq 0 ]; then
            tmux send-keys -t "$SESSION:main" "claude --context ctf -p '/ctf-start && 以下の${category}問題を順番に解いて: ${problems}'" Enter
        else
            tmux new-window -t "$SESSION" -n "$category"
            tmux send-keys -t "$SESSION:$category" "claude --context ctf -p '/ctf-start && 以下の${category}問題を順番に解いて: ${problems}'" Enter
        fi

        ((window++))
        [ $window -ge $PARALLEL_COUNT ] && break
    done

    echo "tmuxセッション '$SESSION' を開始しました"
    echo ""
    echo "確認: tmux attach -t $SESSION"
    echo "一覧: tmux list-windows -t $SESSION"
    echo ""
else
    echo "tmuxがインストールされていません"
    echo ""
    echo "手動で以下を別ターミナルで実行してください:"
    echo ""

    for category_file in "$OUTPUT_DIR"/*.txt; do
        [ -s "$category_file" ] || continue
        category=$(basename "$category_file" .txt)
        problems=$(cat "$category_file" | head -5 | tr '\n' ',' | sed 's/,$//')
        echo "# $category"
        echo "claude --context ctf -p '/ctf-start && 以下の問題を解いて: ${problems}'"
        echo ""
    done
fi

echo "=== 結果確認 ==="
echo "進捗: cat .ctf/progress.json"
echo "フラグ: grep -r 'FLAG{' $OUTPUT_DIR/"
