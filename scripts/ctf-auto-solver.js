#!/usr/bin/env node
/**
 * CTF Auto Solver - 問題自動取得＆自動回答
 *
 * 使用法:
 *   node ctf-auto-solver.js <platform-url> [options]
 *
 * オプション:
 *   --submit       フラグを自動提出
 *   --parallel N   並列数 (デフォルト: 5)
 *   --timeout N    問題あたりのタイムアウト秒 (デフォルト: 180)
 *   --category X   特定カテゴリのみ (カンマ区切り)
 */

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// 設定
const CONFIG = {
  ctfDir: '.ctf',
  progressFile: '.ctf/progress.json',
  platformFile: '.ctf/platform.json',
  parallelCount: 10,
  timeoutPerProblem: 600, // 秒 (10分)
  flagPatterns: [
    /FLAG\{[^}]+\}/gi,
    /flag\{[^}]+\}/gi,
    /CTF\{[^}]+\}/gi,
    /SECCON\{[^}]+\}/gi,
    /CyberDefense\{[^}]+\}/gi,
    /picoCTF\{[^}]+\}/gi,
  ]
};

// カテゴリ別エージェント
const CATEGORY_AGENTS = {
  web: 'ctf-web',
  crypto: 'ctf-crypto',
  forensics: 'ctf-forensics',
  pwn: 'ctf-pwn',
  reversing: 'ctf-pwn',
  osint: 'ctf-osint',
  misc: 'ctf-orchestrator'
};

/**
 * メイン処理
 */
async function main() {
  const args = process.argv.slice(2);
  const platformUrl = args.find(a => a.startsWith('http'));
  const shouldSubmit = args.includes('--submit');
  const parallelCount = parseInt(args.find(a => a.startsWith('--parallel'))?.split('=')[1] || CONFIG.parallelCount);

  console.log('=== CTF Auto Solver ===');
  console.log(`Platform: ${platformUrl || 'manual'}`);
  console.log(`Submit: ${shouldSubmit}`);
  console.log(`Parallel: ${parallelCount}`);
  console.log('');

  // 1. 問題取得
  console.log('[1/5] 問題を取得中...');
  const problems = await fetchProblems(platformUrl);
  console.log(`  → ${problems.length}問を取得`);

  // 2. 分類・優先順位付け
  console.log('[2/5] 問題を分類中...');
  const classified = classifyProblems(problems);
  console.log(`  → カテゴリ別: ${Object.keys(classified).map(k => `${k}(${classified[k].length})`).join(', ')}`);

  // 3. 進捗ファイル初期化
  initProgress(problems);

  // 4. 並列解析
  console.log('[3/5] 並列解析開始...');
  const results = await solveParallel(classified, parallelCount);

  // 5. フラグ提出
  if (shouldSubmit) {
    console.log('[4/5] フラグを提出中...');
    await submitFlags(results, platformUrl);
  } else {
    console.log('[4/5] 提出スキップ (--submit で有効化)');
  }

  // 6. レポート
  console.log('[5/5] 結果レポート');
  generateReport(results);
}

/**
 * 問題を取得（Playwright MCP経由）
 */
async function fetchProblems(url) {
  // platform.jsonがあれば使用
  if (fs.existsSync(CONFIG.platformFile)) {
    const platform = JSON.parse(fs.readFileSync(CONFIG.platformFile, 'utf8'));
    return await fetchFromPlatform(platform);
  }

  // problems.jsonがあれば使用
  if (fs.existsSync('problems.json')) {
    const data = JSON.parse(fs.readFileSync('problems.json', 'utf8'));
    return data.problems || [];
  }

  // Playwright MCPで取得を試みる
  if (url) {
    return await fetchWithPlaywright(url);
  }

  console.error('問題ソースが見つかりません。problems.json または platform.json を作成してください。');
  process.exit(1);
}

/**
 * Playwrightで問題取得
 */
async function fetchWithPlaywright(url) {
  // Claude に Playwright MCP 経由で取得させる
  const prompt = `
Playwright MCPを使って ${url} から問題一覧を取得してください。

手順:
1. URLにアクセス
2. ログインが必要な場合はplatform.jsonの認証情報を使用
3. 問題一覧ページをスクレイピング
4. 各問題の詳細（タイトル、カテゴリ、配点、説明、添付ファイル）を取得
5. 結果を problems.json として保存

出力形式:
{
  "problems": [
    {"name": "問題名", "category": "web", "points": 100, "description": "...", "files": ["file.txt"]}
  ]
}
`;

  console.log('  → Playwright MCPで取得を試行...');

  // 実際のClaude呼び出しはここで行う
  // この部分は claude コマンドで実行される想定

  return [];
}

/**
 * プラットフォーム設定から取得
 */
async function fetchFromPlatform(platform) {
  // CTFd, rCTF などのプラットフォーム別処理
  // 実際はPlaywright MCPで実行
  return [];
}

/**
 * 問題をカテゴリ別に分類
 */
function classifyProblems(problems) {
  const classified = {};

  // 配点順にソート
  const sorted = problems.sort((a, b) => (a.points || 0) - (b.points || 0));

  for (const problem of sorted) {
    const category = (problem.category || 'misc').toLowerCase();
    if (!classified[category]) {
      classified[category] = [];
    }
    classified[category].push(problem);
  }

  return classified;
}

/**
 * 進捗ファイル初期化
 */
function initProgress(problems) {
  if (!fs.existsSync(CONFIG.ctfDir)) {
    fs.mkdirSync(CONFIG.ctfDir, { recursive: true });
  }

  const progress = {
    startTime: new Date().toISOString(),
    totalProblems: problems.length,
    solved: 0,
    problems: problems.map(p => ({
      name: p.name,
      category: p.category,
      points: p.points,
      status: 'pending',
      flag: null,
      solvedAt: null
    }))
  };

  fs.writeFileSync(CONFIG.progressFile, JSON.stringify(progress, null, 2));
}

/**
 * 並列解析実行
 */
async function solveParallel(classified, parallelCount) {
  const results = [];
  const categories = Object.keys(classified);

  // tmuxセッション作成
  const sessionName = `ctf-auto-${Date.now()}`;

  try {
    execSync(`tmux kill-session -t ${sessionName} 2>/dev/null || true`);
    execSync(`tmux new-session -d -s ${sessionName} -n main`);

    let windowIndex = 0;
    for (const category of categories.slice(0, parallelCount)) {
      const problems = classified[category];
      const agent = CATEGORY_AGENTS[category] || 'ctf-orchestrator';
      const problemNames = problems.map(p => p.name).join(', ');

      const cmd = `claude --context ctf -p "以下の${category}問題を順番に解いて。10分で進展なければスキップ。フラグが見つかったら /ctf-flag で記録: ${problemNames}"`;

      if (windowIndex === 0) {
        execSync(`tmux send-keys -t ${sessionName}:main '${cmd}' Enter`);
      } else {
        execSync(`tmux new-window -t ${sessionName} -n ${category}`);
        execSync(`tmux send-keys -t ${sessionName}:${category} '${cmd}' Enter`);
      }

      windowIndex++;
    }

    console.log(`  → tmuxセッション '${sessionName}' で${windowIndex}並列実行中`);
    console.log(`  → 監視: tmux attach -t ${sessionName}`);

  } catch (e) {
    console.log('  → tmuxなし: 順次実行モード');
    // tmuxがない場合は順次実行
  }

  return results;
}

/**
 * フラグ提出
 */
async function submitFlags(results, url) {
  // progress.jsonから解決済み問題を取得
  if (!fs.existsSync(CONFIG.progressFile)) return;

  const progress = JSON.parse(fs.readFileSync(CONFIG.progressFile, 'utf8'));
  const solved = progress.problems.filter(p => p.status === 'solved' && p.flag);

  console.log(`  → ${solved.length}問のフラグを提出`);

  // Playwright MCPで提出（実際はClaudeに依頼）
  for (const problem of solved) {
    console.log(`    - ${problem.name}: ${problem.flag}`);
  }
}

/**
 * レポート生成
 */
function generateReport(results) {
  if (!fs.existsSync(CONFIG.progressFile)) return;

  const progress = JSON.parse(fs.readFileSync(CONFIG.progressFile, 'utf8'));

  const solved = progress.problems.filter(p => p.status === 'solved');
  const pending = progress.problems.filter(p => p.status === 'pending');
  const skipped = progress.problems.filter(p => p.status === 'skipped');

  const totalPoints = solved.reduce((sum, p) => sum + (p.points || 0), 0);

  console.log('');
  console.log('=== 結果サマリー ===');
  console.log(`解決: ${solved.length}問 (${totalPoints}pts)`);
  console.log(`未着手: ${pending.length}問`);
  console.log(`スキップ: ${skipped.length}問`);
  console.log('');

  if (solved.length > 0) {
    console.log('解決した問題:');
    for (const p of solved) {
      console.log(`  ✓ ${p.name} (${p.category}, ${p.points}pts) - ${p.flag}`);
    }
  }

  if (skipped.length > 0) {
    console.log('');
    console.log('スキップした問題:');
    for (const p of skipped) {
      console.log(`  ✗ ${p.name} (${p.category}, ${p.points}pts)`);
    }
  }
}

// 実行
main().catch(console.error);
