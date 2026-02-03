#!/bin/bash
# CTF Claude Code インストールスクリプト

set -e

CLAUDE_DIR="$HOME/.claude"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "CTF Claude Code をインストールしています..."

# ディレクトリ作成
mkdir -p "$CLAUDE_DIR"/{agents,commands,rules,contexts,skills,scripts/hooks,scripts/lib,templates}

# Agents
echo "  - Agents をコピー中..."
cp "$REPO_DIR"/agents/*.md "$CLAUDE_DIR/agents/"

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
echo "     （README.md の「Hooks（フック）の導入」セクションを参照）"
echo ""
echo "  2. CTFモードで起動:"
echo "     claude --context ctf"
echo ""
echo "  3. セッション開始:"
echo "     /ctf-start"
