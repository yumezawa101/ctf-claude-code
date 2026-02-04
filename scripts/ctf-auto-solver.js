#!/usr/bin/env node
/**
 * CTF Auto Solver - 対話式問題自動取得＆自動回答
 *
 * 使用法:
 *   node ctf-auto-solver.js
 *
 * 対話形式で以下を設定:
 *   - プラットフォームURL (空欄でproblems.json使用)
 *   - ログイン情報 (URL指定時)
 *   - カテゴリ絞り込み
 *   - 解きたい問題
 *   - 配点フィルタ
 *   - フラグ自動提出
 */

const { execSync } = require('child_process');
const fs = require('fs');
const readline = require('readline');

// 設定
const CONFIG = {
  ctfDir: '.ctf',
  progressFile: '.ctf/progress.json',
  platformFile: '.ctf/platform.json',
  problemsFile: 'problems.json',
  parallelCount: 10,
  timeoutPerProblem: 300, // 秒 (5分)
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
 * 対話式入力
 */
function createPrompt() {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
}

async function ask(rl, question, defaultValue = '') {
  return new Promise((resolve) => {
    const hint = defaultValue ? ` (空欄: ${defaultValue})` : '';
    rl.question(`${question}${hint}: `, (answer) => {
      resolve(answer.trim() || defaultValue);
    });
  });
}

async function askPassword(rl, question) {
  return new Promise((resolve) => {
    rl.question(`${question}: `, (answer) => {
      resolve(answer.trim());
    });
  });
}

async function askYesNo(rl, question, defaultNo = true) {
  return new Promise((resolve) => {
    const hint = defaultNo ? ' [y/N]' : ' [Y/n]';
    rl.question(`${question}${hint}: `, (answer) => {
      const a = answer.trim().toLowerCase();
      if (defaultNo) {
        resolve(a === 'y' || a === 'yes');
      } else {
        resolve(a !== 'n' && a !== 'no');
      }
    });
  });
}

/**
 * 対話形式で設定を取得
 */
async function getConfig() {
  const rl = createPrompt();

  console.log('');
  console.log('┌─────────────────────────────────────────────────────────┐');
  console.log('│ CTF Auto Solver - 設定                                   │');
  console.log('├─────────────────────────────────────────────────────────┤');
  console.log('');

  const config = {};

  // [1] URL
  console.log('[1] プラットフォームURL');
  config.url = await ask(rl, '    URL', 'problems.jsonを使用');
  if (config.url === 'problems.jsonを使用') {
    config.url = '';
  }
  console.log('');

  // [2] ログイン情報 (URL指定時のみ)
  if (config.url) {
    console.log('[2] ログイン情報');
    config.username = await ask(rl, '    ユーザー名');
    config.password = await askPassword(rl, '    パスワード');
    console.log('');
  }

  // [3] カテゴリ
  console.log('[3] カテゴリ絞り込み (web,crypto,forensics,pwn,osint)');
  const categoryInput = await ask(rl, '    カテゴリ', '全カテゴリ');
  config.categories = categoryInput === '全カテゴリ'
    ? []
    : categoryInput.split(',').map(c => c.trim().toLowerCase());
  console.log('');

  // [4] 問題名
  console.log('[4] 解きたい問題 (カンマ区切り)');
  const problemsInput = await ask(rl, '    問題名', '全問題');
  config.problemNames = problemsInput === '全問題'
    ? []
    : problemsInput.split(',').map(p => p.trim());
  console.log('');

  // [5] 配点フィルタ
  console.log('[5] 配点フィルタ');
  const minPoints = await ask(rl, '    最小配点', '0');
  const maxPoints = await ask(rl, '    最大配点', '制限なし');
  config.minPoints = parseInt(minPoints) || 0;
  config.maxPoints = maxPoints === '制限なし' ? Infinity : (parseInt(maxPoints) || Infinity);
  console.log('');

  // [6] 自動提出
  console.log('[6] フラグ自動提出');
  config.autoSubmit = await askYesNo(rl, '    自動提出する?', true);
  console.log('');

  rl.close();

  console.log('└─────────────────────────────────────────────────────────┘');
  console.log('');

  return config;
}

/**
 * 設定内容を表示
 */
function showConfig(config) {
  console.log('=== 設定確認 ===');
  console.log(`URL: ${config.url || '(problems.json使用)'}`);
  if (config.url) {
    console.log(`ユーザー名: ${config.username || '(未設定)'}`);
    console.log(`パスワード: ${config.password ? '********' : '(未設定)'}`);
  }
  console.log(`カテゴリ: ${config.categories.length ? config.categories.join(', ') : '全て'}`);
  console.log(`問題: ${config.problemNames.length ? config.problemNames.join(', ') : '全て'}`);
  console.log(`配点: ${config.minPoints} - ${config.maxPoints === Infinity ? '∞' : config.maxPoints}`);
  console.log(`自動提出: ${config.autoSubmit ? 'Yes' : 'No'}`);
  console.log('');
}

/**
 * メイン処理
 */
async function main() {
  console.log('=== CTF Auto Solver ===');

  // 対話形式で設定取得
  const config = await getConfig();
  showConfig(config);

  // 1. 問題取得
  console.log('[1/5] 問題を取得中...');
  let problems = await fetchProblems(config);
  console.log(`  → ${problems.length}問を取得`);

  // 2. フィルタリング
  console.log('[2/5] フィルタリング...');
  problems = filterProblems(problems, config);
  console.log(`  → ${problems.length}問が対象`);

  if (problems.length === 0) {
    console.log('対象の問題がありません。');
    return;
  }

  // 3. 分類・優先順位付け
  console.log('[3/5] 問題を分類中...');
  const classified = classifyProblems(problems);
  console.log(`  → カテゴリ別: ${Object.keys(classified).map(k => `${k}(${classified[k].length})`).join(', ')}`);

  // 4. 進捗ファイル初期化
  initProgress(problems, config);

  // 5. 並列解析
  console.log('[4/5] 並列解析開始...');
  const results = await solveParallel(classified, CONFIG.parallelCount);

  // 6. フラグ提出
  if (config.autoSubmit) {
    console.log('[5/5] フラグを提出中...');
    await submitFlags(results, config);
  } else {
    console.log('[5/5] 提出スキップ (自動提出=No)');
  }

  // 7. レポート
  console.log('');
  generateReport(results);
}

/**
 * 問題を取得
 */
async function fetchProblems(config) {
  // URL指定時はPlaywright MCPで取得
  if (config.url) {
    // platform.jsonを一時的に作成
    const platformConfig = {
      type: 'auto',
      url: config.url,
      credentials: {
        username: config.username,
        password: config.password
      }
    };

    if (!fs.existsSync(CONFIG.ctfDir)) {
      fs.mkdirSync(CONFIG.ctfDir, { recursive: true });
    }
    fs.writeFileSync(CONFIG.platformFile, JSON.stringify(platformConfig, null, 2));

    console.log('  → Playwright MCPで取得を試行...');
    // 実際のClaude呼び出しはここで行う
    return [];
  }

  // problems.jsonがあれば使用
  if (fs.existsSync(CONFIG.problemsFile)) {
    const data = JSON.parse(fs.readFileSync(CONFIG.problemsFile, 'utf8'));
    return data.problems || [];
  }

  console.error('問題ソースが見つかりません。URLを指定するか、problems.json を作成してください。');
  process.exit(1);
}

/**
 * 問題をフィルタリング
 */
function filterProblems(problems, config) {
  return problems.filter(p => {
    // カテゴリフィルタ
    if (config.categories.length > 0) {
      const cat = (p.category || 'misc').toLowerCase();
      if (!config.categories.includes(cat)) {
        return false;
      }
    }

    // 問題名フィルタ
    if (config.problemNames.length > 0) {
      if (!config.problemNames.some(name =>
        p.name.toLowerCase().includes(name.toLowerCase())
      )) {
        return false;
      }
    }

    // 配点フィルタ
    const points = p.points || 0;
    if (points < config.minPoints || points > config.maxPoints) {
      return false;
    }

    return true;
  });
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
function initProgress(problems, config) {
  if (!fs.existsSync(CONFIG.ctfDir)) {
    fs.mkdirSync(CONFIG.ctfDir, { recursive: true });
  }

  const progress = {
    startTime: new Date().toISOString(),
    config: {
      url: config.url || null,
      categories: config.categories,
      problemNames: config.problemNames,
      minPoints: config.minPoints,
      maxPoints: config.maxPoints === Infinity ? null : config.maxPoints,
      autoSubmit: config.autoSubmit
    },
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
      const problemNames = problems.map(p => p.name).join(', ');

      const cmd = `claude --context ctf -p "以下の${category}問題を順番に解いて。5分で進展なければスキップ。フラグが見つかったら /ctf-flag で記録: ${problemNames}"`;

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
  }

  return results;
}

/**
 * フラグ提出
 */
async function submitFlags(results, config) {
  if (!fs.existsSync(CONFIG.progressFile)) return;

  const progress = JSON.parse(fs.readFileSync(CONFIG.progressFile, 'utf8'));
  const solved = progress.problems.filter(p => p.status === 'solved' && p.flag);

  console.log(`  → ${solved.length}問のフラグを提出`);

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
