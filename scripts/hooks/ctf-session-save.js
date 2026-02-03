#!/usr/bin/env node
/**
 * CTFセッション終了時に解法パターンを自動抽出・保存
 */
const fs = require('fs');
const path = require('path');

const CTF_DIR = path.join(process.cwd(), '.ctf');
const PROGRESS_FILE = path.join(CTF_DIR, 'progress.json');
const INSTINCTS_FILE = path.join(process.cwd(), 'skills', 'ctf-learning', 'instincts.json');
const SESSION_LOG = path.join(CTF_DIR, 'session-log.json');

// stdinから入力を読み取る
let input = '';
process.stdin.on('data', chunk => {
  input += chunk;
});

process.stdin.on('end', () => {
  try {
    processSession();
  } catch (e) {
    // エラーは無視
  }

  // 入力をそのまま出力（パススルー）
  console.log(input);
});

function processSession() {
  if (!fs.existsSync(PROGRESS_FILE)) return;

  const progress = JSON.parse(fs.readFileSync(PROGRESS_FILE, 'utf8'));
  const solved = progress.problems.filter(p => p.status === 'solved');
  const total = progress.problems.length;

  if (total === 0) return;

  // 統計表示
  console.error(`\n📊 [CTF Session] ${solved.length}/${total} 問完了`);

  // 解答時間の計算
  let totalTime = 0;
  for (const p of solved) {
    if (p.started_at && p.solved_at) {
      totalTime += new Date(p.solved_at) - new Date(p.started_at);
    }
  }

  if (totalTime > 0) {
    const minutes = Math.round(totalTime / 60000);
    console.error(`⏱️  合計解答時間: ${minutes}分`);
  }

  // 解法パターンの自動抽出・学習
  if (solved.length > 0) {
    learnFromSolved(solved, progress);
  }

  // 未解決問題の一覧
  const unsolved = progress.problems.filter(p => p.status !== 'solved');
  if (unsolved.length > 0) {
    console.error(`\n⏸️  未解決: ${unsolved.map(p => p.name).join(', ')}`);
  }
}

/**
 * 解決済み問題から学習
 */
function learnFromSolved(solved, progress) {
  // instincts.jsonを読み込み
  let instincts = { instincts: [], negative_patterns: [], contest_patterns: {} };
  if (fs.existsSync(INSTINCTS_FILE)) {
    try {
      instincts = JSON.parse(fs.readFileSync(INSTINCTS_FILE, 'utf8'));
    } catch (e) {
      // パースエラーは無視
    }
  }

  let learnedCount = 0;

  // 各問題の解法を分析
  for (const problem of solved) {
    // 問題に記録されたコマンド履歴があれば分析
    if (problem.commands && problem.commands.length > 0) {
      const patterns = extractPatterns(problem);
      for (const pattern of patterns) {
        if (updateInstinct(instincts, pattern)) {
          learnedCount++;
        }
      }
    }

    // 解法メモがあれば記録
    if (problem.solution_note) {
      recordSolutionNote(problem, instincts);
    }
  }

  // 大会パターンの記録
  const contestName = progress.contest || process.env.CTF_CONTEST || 'unknown';
  if (!instincts.contest_patterns[contestName]) {
    instincts.contest_patterns[contestName] = {
      date: new Date().toISOString().split('T')[0],
      solved: 0,
      categories: {}
    };
  }

  instincts.contest_patterns[contestName].solved += solved.length;

  // カテゴリ別集計
  for (const p of solved) {
    const cat = p.category || 'misc';
    if (!instincts.contest_patterns[contestName].categories[cat]) {
      instincts.contest_patterns[contestName].categories[cat] = 0;
    }
    instincts.contest_patterns[contestName].categories[cat]++;
  }

  // 保存
  try {
    const dir = path.dirname(INSTINCTS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(INSTINCTS_FILE, JSON.stringify(instincts, null, 2));

    if (learnedCount > 0) {
      console.error(`\n🧠 ${learnedCount}個の新しいパターンを学習しました`);
    }
  } catch (e) {
    console.error(`\n⚠️  学習データの保存に失敗: ${e.message}`);
  }
}

/**
 * 解法からパターンを抽出
 */
function extractPatterns(problem) {
  const patterns = [];
  const category = problem.category || 'misc';

  // 成功したコマンドを分析
  const commands = problem.commands || [];

  // よくあるパターンをチェック
  const patternMatchers = [
    {
      regex: /base64\s+-d|base64\s+--decode/i,
      trigger: 'Base64エンコード文字列',
      action: 'base64 -d でデコード'
    },
    {
      regex: /sqlmap/i,
      trigger: 'SQLインジェクションの可能性',
      action: 'sqlmap で自動検出'
    },
    {
      regex: /binwalk\s+-e/i,
      trigger: '埋め込みファイルの可能性',
      action: 'binwalk -e で抽出'
    },
    {
      regex: /strings.*grep.*flag/i,
      trigger: 'バイナリ内にフラグ文字列',
      action: 'strings | grep flag'
    },
    {
      regex: /exiftool/i,
      trigger: '画像ファイルのメタデータ',
      action: 'exiftool で確認'
    },
    {
      regex: /zsteg/i,
      trigger: 'PNG/BMPステガノグラフィ',
      action: 'zsteg で解析'
    },
    {
      regex: /steghide.*extract/i,
      trigger: 'JPEGステガノグラフィ',
      action: 'steghide extract'
    },
    {
      regex: /john|hashcat/i,
      trigger: 'パスワードハッシュ',
      action: 'john または hashcat で解析'
    },
    {
      regex: /gobuster|ffuf|dirb/i,
      trigger: '隠しディレクトリ/ファイル',
      action: 'ディレクトリ列挙ツール'
    },
    {
      regex: /ROPgadget|one_gadget/i,
      trigger: 'ROP攻撃',
      action: 'ROPgadget/one_gadget でガジェット検索'
    },
    {
      regex: /volatility|vol\.py/i,
      trigger: 'メモリダンプ',
      action: 'volatility3 で解析'
    },
    {
      regex: /tshark|wireshark/i,
      trigger: 'PCAP/ネットワークキャプチャ',
      action: 'tshark/wireshark で通信解析'
    },
    {
      regex: /curl.*-X\s*POST|curl.*-d/i,
      trigger: 'POSTリクエスト',
      action: 'curl -X POST でパラメータ送信'
    },
    {
      regex: /pwntools|from pwn import/i,
      trigger: 'Pwn問題',
      action: 'pwntools でExploit作成'
    },
    {
      regex: /factordb|sage|sympy/i,
      trigger: 'RSA素因数分解',
      action: 'factordb/sage で因数分解'
    }
  ];

  for (const cmd of commands) {
    const cmdStr = typeof cmd === 'string' ? cmd : cmd.command;
    if (!cmdStr) continue;

    for (const matcher of patternMatchers) {
      if (matcher.regex.test(cmdStr)) {
        patterns.push({
          trigger: matcher.trigger,
          action: matcher.action,
          category: category,
          problem: problem.name
        });
        break; // 1コマンド1パターンまで
      }
    }
  }

  return patterns;
}

/**
 * instinctを更新（既存があれば信頼度UP、なければ追加）
 * @returns {boolean} 新規追加の場合true
 */
function updateInstinct(instincts, newPattern) {
  const existing = instincts.instincts.find(
    i => i.trigger === newPattern.trigger && i.category === newPattern.category
  );

  if (existing) {
    // 既存パターン: 信頼度と使用回数を更新
    existing.source_count = (existing.source_count || 0) + 1;
    existing.confidence = Math.min(0.99, (existing.confidence || 0.5) + 0.02);
    existing.last_used = new Date().toISOString();
    return false;
  } else {
    // 新規パターン
    instincts.instincts.push({
      trigger: newPattern.trigger,
      action: newPattern.action,
      category: newPattern.category,
      confidence: 0.60,
      source_count: 1,
      first_seen: new Date().toISOString(),
      last_used: new Date().toISOString()
    });
    return true;
  }
}

/**
 * 解法メモを記録
 */
function recordSolutionNote(problem, instincts) {
  const category = problem.category || 'misc';
  const note = problem.solution_note;

  // シンプルなトリガー→アクションの抽出を試みる
  const match = note.match(/(.+?)(?:→|->|：|:)\s*(.+)/);
  if (match) {
    const trigger = match[1].trim();
    const action = match[2].trim();

    if (trigger.length > 5 && action.length > 5) {
      updateInstinct(instincts, {
        trigger: trigger,
        action: action,
        category: category,
        problem: problem.name
      });
    }
  }
}
