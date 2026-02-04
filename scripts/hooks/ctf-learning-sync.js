#!/usr/bin/env node
/**
 * 学習データを ~/.claude/rules/ctf-learned.md に同期
 * 高信頼度のパターンを新しいセッションでも即座に参照できるようにする
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

const LEARNING_DIR = path.join(os.homedir(), '.claude', 'skills', 'ctf-learning');
const INSTINCTS_FILE = path.join(LEARNING_DIR, 'instincts.json');
const RULES_DIR = path.join(os.homedir(), '.claude', 'rules');
const LEARNED_RULES_FILE = path.join(RULES_DIR, 'ctf-learned.md');

// 信頼度のしきい値（これ以上のパターンをルールに反映）
const CONFIDENCE_THRESHOLD = 0.70;
const MIN_SOURCE_COUNT = 2;

/**
 * 学習データをルールファイルに同期
 */
function syncLearningToRules() {
  if (!fs.existsSync(INSTINCTS_FILE)) {
    return;
  }

  try {
    const instincts = JSON.parse(fs.readFileSync(INSTINCTS_FILE, 'utf8'));

    // 高信頼度パターンをフィルタ
    const highConfidencePatterns = instincts.instincts.filter(
      i => i.confidence >= CONFIDENCE_THRESHOLD && (i.source_count || 0) >= MIN_SOURCE_COUNT
    );

    if (highConfidencePatterns.length === 0) {
      return;
    }

    // カテゴリ別に分類
    const byCategory = {};
    for (const p of highConfidencePatterns) {
      const cat = p.category || 'misc';
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push(p);
    }

    // ルールファイルを生成
    let content = `# CTF 学習済みパターン（自動生成）

> このファイルは問題を解くたびに自動更新されます。
> 信頼度 ${CONFIDENCE_THRESHOLD * 100}% 以上、${MIN_SOURCE_COUNT}回以上使用されたパターンを反映。
> 最終更新: ${new Date().toISOString().split('T')[0]}

## 即座に試すべきパターン

`;

    for (const [category, patterns] of Object.entries(byCategory)) {
      content += `### ${category.toUpperCase()}\n\n`;

      // 信頼度でソート
      patterns.sort((a, b) => b.confidence - a.confidence);

      for (const p of patterns) {
        const confidence = Math.round(p.confidence * 100);
        content += `- **${p.trigger}** → ${p.action} (信頼度: ${confidence}%, ${p.source_count}回使用)\n`;
      }
      content += '\n';
    }

    // 統計情報
    content += `## 統計

- 総パターン数: ${instincts.instincts.length}
- 高信頼度パターン: ${highConfidencePatterns.length}
`;

    // 大会別パターン
    if (Object.keys(instincts.contest_patterns || {}).length > 0) {
      content += '\n## 大会別実績\n\n';
      for (const [contest, data] of Object.entries(instincts.contest_patterns)) {
        content += `- **${contest}**: ${data.solved}問解決`;
        if (data.categories) {
          const cats = Object.entries(data.categories).map(([k, v]) => `${k}:${v}`).join(', ');
          content += ` (${cats})`;
        }
        content += '\n';
      }
    }

    // ルールディレクトリがなければ作成
    if (!fs.existsSync(RULES_DIR)) {
      fs.mkdirSync(RULES_DIR, { recursive: true });
    }

    fs.writeFileSync(LEARNED_RULES_FILE, content);
    console.error(`📚 学習データを同期: ${LEARNED_RULES_FILE}`);
    console.error(`   ${highConfidencePatterns.length}個の高信頼度パターンを反映`);

  } catch (e) {
    console.error(`⚠️ 学習データ同期エラー: ${e.message}`);
  }
}

// メイン実行
syncLearningToRules();
