#!/bin/bash
# CTF Claude Code インストールスクリプト

set -e

CLAUDE_DIR="$HOME/.claude"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="$REPO_DIR/config/settings.json"

echo "CTF Claude Code をインストールしています..."

# ディレクトリ作成
mkdir -p "$CLAUDE_DIR"/{agents,commands,rules,contexts,skills,scripts/hooks,scripts/lib,templates,config}

# 設定ファイルをコピー
echo "  - 設定ファイルをコピー中..."
cp "$REPO_DIR"/config/*.json "$CLAUDE_DIR/config/"

# モデル設定を読み込む関数
get_model() {
  local agent_name="$1"
  local default_model="opus"

  # jqがインストールされている場合は設定から読み込む
  if command -v jq &> /dev/null && [ -f "$CONFIG_FILE" ]; then
    local model=$(jq -r ".models.agents.\"$agent_name\" // .models.default // \"$default_model\"" "$CONFIG_FILE" 2>/dev/null)
    if [ "$model" != "null" ] && [ -n "$model" ]; then
      echo "$model"
      return
    fi
  fi

  echo "$default_model"
}

# エージェントファイルのモデルを設定に基づいて更新
update_agent_model() {
  local file="$1"
  local agent_name=$(basename "$file" .md)
  local model=$(get_model "$agent_name")

  # model: 行を更新
  if grep -q "^model:" "$file"; then
    sed -i "s/^model:.*$/model: $model/" "$file"
  fi
}

# Agents をコピーしてモデル設定を適用
echo "  - Agents をコピー中..."
for agent_file in "$REPO_DIR"/agents/*.md; do
  cp "$agent_file" "$CLAUDE_DIR/agents/"
  local_file="$CLAUDE_DIR/agents/$(basename "$agent_file")"
  update_agent_model "$local_file"
done

# 適用されたモデル設定を表示
echo ""
echo "  モデル設定:"
for agent_file in "$CLAUDE_DIR"/agents/ctf-*.md; do
  agent_name=$(basename "$agent_file" .md)
  model=$(grep "^model:" "$agent_file" | cut -d' ' -f2)
  echo "    - $agent_name: $model"
done
echo ""

# Commands
echo "  - Commands をコピー中..."
cp "$REPO_DIR"/commands/*.md "$CLAUDE_DIR/commands/"

# Rules
echo "  - Rules をコピー中..."
cp "$REPO_DIR"/rules/*.md "$CLAUDE_DIR/rules/"

# Contexts
echo "  - Contexts をコピー中..."
cp "$REPO_DIR"/contexts/*.md "$CLAUDE_DIR/contexts/"

# Skills
echo "  - Skills をコピー中..."
cp -r "$REPO_DIR"/skills/* "$CLAUDE_DIR/skills/"

# Hook スクリプト
echo "  - Hook スクリプトをコピー中..."
cp "$REPO_DIR"/scripts/hooks/*.js "$CLAUDE_DIR/scripts/hooks/"

# ライブラリ
echo "  - ライブラリをコピー中..."
cp "$REPO_DIR"/scripts/lib/*.js "$CLAUDE_DIR/scripts/lib/"

# テンプレート
echo "  - テンプレートをコピー中..."
cp "$REPO_DIR"/templates/* "$CLAUDE_DIR/templates/"

# MCP設定
echo "  - MCP設定をコピー中..."
cp "$REPO_DIR"/mcp-configs/*.json "$CLAUDE_DIR/"

# .ctf ディレクトリ
echo "  - CTF進捗管理テンプレートをコピー中..."
mkdir -p "$CLAUDE_DIR/.ctf"
cp "$REPO_DIR"/.ctf/*.json "$CLAUDE_DIR/.ctf/"

echo ""
echo "インストール完了!"
echo ""
echo "次のステップ:"
echo "  1. ~/.claude/settings.json に hooks 設定を追加してください"
echo "     （README.md の「Hooks設定」セクションを参照）"
echo ""
echo "  2. CTFモードで起動:"
echo "     claude --context ctf"
echo ""
echo "  3. セッション開始:"
echo "     /ctf-start"
echo ""
echo "モデル設定を変更するには:"
echo "  config/settings.json を編集して再度 ./install.sh を実行"
