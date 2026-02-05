#!/usr/bin/env node
/**
 * Bash出力からフラグパターンを検出し、自動記録・即時学習する
 * パターン: FLAG{...}, flag{...}, ctf{...}, [大会名]{...}
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

const CTF_DIR = path.join(process.cwd(), 'ctf_workspace');
const PROGRESS_FILE = path.join(CTF_DIR, 'progress.json');
const COMMAND_LOG_FILE = path.join(CTF_DIR, 'command-log.json');
const FLAGS_FILE = path.join(CTF_DIR, 'flags.json');
const SOLUTIONS_DIR = path.join(CTF_DIR, 'solutions');

// 学習データの保存先（2箇所に保存）
// 1. ~/.claude/skills/ctf-learning/ (個人用・新セッションで自動参照)
const GLOBAL_LEARNING_DIR = path.join(os.homedir(), '.claude', 'skills', 'ctf-learning');
const GLOBAL_INSTINCTS_FILE = path.join(GLOBAL_LEARNING_DIR, 'instincts.json');
const GLOBAL_PATTERNS_DIR = path.join(GLOBAL_LEARNING_DIR, 'patterns');

// 2. ctf_workspace/learning/ (プロジェクト用・gitコミット可能)
const PROJECT_LEARNING_DIR = path.join(CTF_DIR, 'learning');
const PROJECT_INSTINCTS_FILE = path.join(PROJECT_LEARNING_DIR, 'instincts.json');
const PROJECT_PATTERNS_DIR = path.join(PROJECT_LEARNING_DIR, 'patterns');

// 一般的なCTFフラグパターン
const FLAG_PATTERNS = [
  /FLAG\{[^}]+\}/gi,
  /flag\{[^}]+\}/gi,
  /ctf\{[^}]+\}/gi,
  /CTF\{[^}]+\}/gi,
  // 日本の大会
  /SECCON\{[^}]+\}/gi,
  /CyberDefense\{[^}]+\}/gi,
  /DEFCON\{[^}]+\}/gi,
  // 海外の大会
  /picoCTF\{[^}]+\}/gi,
  /HTB\{[^}]+\}/gi,
  /DUCTF\{[^}]+\}/gi,
  /CSAW\{[^}]+\}/gi,
  /hxp\{[^}]+\}/gi,
  /dice\{[^}]+\}/gi,
];

// コマンドからパターンを抽出するマッチャー
const PATTERN_MATCHERS = [
  { regex: /base64\s+-d|base64\s+--decode/i, trigger: 'Base64エンコード文字列', action: 'base64 -d でデコード' },
  { regex: /sqlmap/i, trigger: 'SQLインジェクションの可能性', action: 'sqlmap で自動検出' },
  { regex: /binwalk\s+-e/i, trigger: '埋め込みファイルの可能性', action: 'binwalk -e で抽出' },
  { regex: /strings.*grep.*flag/i, trigger: 'バイナリ内にフラグ文字列', action: 'strings | grep flag' },
  { regex: /exiftool/i, trigger: '画像ファイルのメタデータ', action: 'exiftool で確認' },
  { regex: /zsteg/i, trigger: 'PNG/BMPステガノグラフィ', action: 'zsteg で解析' },
  { regex: /steghide.*extract/i, trigger: 'JPEGステガノグラフィ', action: 'steghide extract' },
  { regex: /john|hashcat/i, trigger: 'パスワードハッシュ', action: 'john または hashcat で解析' },
  { regex: /gobuster|ffuf|dirb/i, trigger: '隠しディレクトリ/ファイル', action: 'ディレクトリ列挙ツール' },
  { regex: /ROPgadget|one_gadget/i, trigger: 'ROP攻撃', action: 'ROPgadget/one_gadget でガジェット検索' },
  { regex: /volatility|vol\.py/i, trigger: 'メモリダンプ', action: 'volatility3 で解析' },
  { regex: /tshark|wireshark/i, trigger: 'PCAP/ネットワークキャプチャ', action: 'tshark/wireshark で通信解析' },
  { regex: /curl.*-X\s*POST|curl.*-d/i, trigger: 'POSTリクエスト', action: 'curl -X POST でパラメータ送信' },
  { regex: /pwntools|from pwn import/i, trigger: 'Pwn問題', action: 'pwntools でExploit作成' },
  { regex: /factordb|sage|sympy/i, trigger: 'RSA素因数分解', action: 'factordb/sage で因数分解' },
  { regex: /xxd\s+-r|unhex/i, trigger: 'Hexエンコード', action: 'xxd -r でデコード' },
  { regex: /openssl\s+rsautl/i, trigger: 'RSA復号', action: 'openssl rsautl -decrypt' },
  { regex: /nc\s+-l|ncat/i, trigger: 'リバースシェル', action: 'nc -lvp でリスナー' },
  { regex: /gdb|r2|radare2/i, trigger: 'バイナリ解析', action: 'gdb/radare2 でデバッグ' },
  { regex: /curl.*robots\.txt/i, trigger: 'robots.txt確認', action: 'curl robots.txt で隠しパス発見' },
  { regex: /\.git\/HEAD|git-dumper/i, trigger: 'Git情報漏洩', action: '.git/ ディレクトリを復元' },
  { regex: /jwt_tool|jwt\.io/i, trigger: 'JWT脆弱性', action: 'jwt_tool で解析・改ざん' },
  { regex: /feroxbuster/i, trigger: 'ディレクトリ列挙', action: 'feroxbuster で高速スキャン' },
];

// 設定
const MAX_COMMANDS = 20;  // コマンド履歴上限（100 → 20に削減）
const OUTPUT_TRUNCATE_LENGTH = 200;  // 出力の最大文字数

// stdinから入力を読み取る
let input = '';
process.stdin.on('data', chunk => {
  input += chunk;
});

process.stdin.on('end', () => {
  try {
    const data = JSON.parse(input);
    const output = data.tool_output?.stdout || data.tool_output?.output || '';
    const command = data.tool_input?.command || '';

    // フラグパターンを検索
    const foundFlags = new Set();

    for (const pattern of FLAG_PATTERNS) {
      const matches = output.match(pattern);
      if (matches) {
        matches.forEach(flag => foundFlags.add(flag));
      }
    }

    const hasFlag = foundFlags.size > 0;

    // コマンドを記録（サマリーのみ、フラグ検出情報付き）
    recordCommand(command, output, hasFlag);

    // フラグが見つかった場合
    if (hasFlag) {
      const flags = Array.from(foundFlags);
      console.error('\n' + '='.repeat(50));
      console.error('🚩 [CTF Hook] フラグを検出しました！');
      console.error('='.repeat(50));

      flags.forEach((flag, i) => {
        console.error(`  ${i + 1}. ${flag}`);
      });

      console.error('\n📝 記録: /ctf-flag ' + flags[0]);

      // progress.jsonを更新
      const problem = updateProgress(flags, command);

      // 📁 flags.json と FLAG.txt に保存
      updateFlagsJson(flags, problem, command);
      saveFlagTxt(flags, problem);

      // 🧠 即時学習: instincts.json のみ更新（patterns/*.md への追記は廃止）
      const learnedPatterns = learnImmediately(problem, command);
      if (learnedPatterns > 0) {
        console.error(`\n🧠 学習完了: ${learnedPatterns}個のパターンを記録`);
      }

      // 📚 学習データをルールファイルに同期
      syncToRulesFile();

      console.error('='.repeat(50) + '\n');

      // フラグ検出時のみサマリーを出力（パススルーせず）
      console.log(JSON.stringify({ flags: flags }));
    }
    // フラグ未検出時はパススルーしない（コンテキスト節約のため）
  } catch (e) {
    // JSONパースエラー時は何も出力しない
  }
});

/**
 * コマンドを記録（学習用）- 出力はサマリー化してコンテキスト節約
 * @param {string} command - 実行されたコマンド
 * @param {string} output - コマンド出力
 * @param {boolean} foundFlag - フラグが検出されたか
 */
function recordCommand(command, output, foundFlag = false) {
  if (!command) return;

  // ctf_workspaceディレクトリがなければ作成
  if (!fs.existsSync(CTF_DIR)) {
    fs.mkdirSync(CTF_DIR, { recursive: true });
  }

  // コマンドログを読み込み
  let commandLog = { commands: [] };
  if (fs.existsSync(COMMAND_LOG_FILE)) {
    try {
      commandLog = JSON.parse(fs.readFileSync(COMMAND_LOG_FILE, 'utf8'));
    } catch (e) {
      // パースエラーは無視
    }
  }

  // 出力はサマリー化（フラグ検出時は検出フラグを記録、それ以外は切り詰め）
  let outputSummary;
  if (foundFlag) {
    // フラグパターンを抽出
    const flagMatch = output.match(/(?:FLAG|flag|ctf|CTF|SECCON|picoCTF|HTB|DUCTF|CSAW|hxp|dice)\{[^}]+\}/);
    outputSummary = `✓ Flag: ${flagMatch?.[0] || 'detected'}`;
  } else {
    // 出力を切り詰め
    outputSummary = output.length > OUTPUT_TRUNCATE_LENGTH
      ? output.slice(0, OUTPUT_TRUNCATE_LENGTH) + '...[truncated]'
      : output;
  }

  // コマンドエントリを追加
  commandLog.commands.push({
    command: command.length > 200 ? command.slice(0, 200) + '...' : command,
    timestamp: new Date().toISOString(),
    output: outputSummary,  // 出力全文ではなくサマリーのみ
    has_flag: foundFlag
  });

  // 最新MAX_COMMANDSコマンドのみ保持（100 → 20に削減）
  if (commandLog.commands.length > MAX_COMMANDS) {
    commandLog.commands = commandLog.commands.slice(-MAX_COMMANDS);
  }

  fs.writeFileSync(COMMAND_LOG_FILE, JSON.stringify(commandLog, null, 2));
}

/**
 * progress.jsonを更新（フラグ検出時）
 * @returns {object|null} 更新された問題オブジェクト
 */
function updateProgress(flags, command) {
  if (!fs.existsSync(PROGRESS_FILE)) return null;

  try {
    const progress = JSON.parse(fs.readFileSync(PROGRESS_FILE, 'utf8'));

    // 検出フラグリスト
    if (!progress.detected_flags) {
      progress.detected_flags = [];
    }

    // 現在進行中の問題を探す
    const currentProblem = progress.problems?.find(p => p.status === 'in_progress');

    flags.forEach(flag => {
      // 検出フラグに追加
      if (!progress.detected_flags.includes(flag)) {
        progress.detected_flags.push(flag);
      }

      // 進行中の問題にフラグとコマンドを記録
      if (currentProblem) {
        currentProblem.flag = flag;
        currentProblem.solved_at = new Date().toISOString();
        currentProblem.status = 'solved';

        // 解決に使用したコマンドを記録（学習用）
        if (!currentProblem.commands) {
          currentProblem.commands = [];
        }
        if (command && !currentProblem.commands.includes(command)) {
          currentProblem.commands.push(command);
        }
      }
    });

    fs.writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
    return currentProblem;
  } catch (e) {
    return null;
  }
}

/**
 * 📁 flags.json を更新（フラグ検出時）
 */
function updateFlagsJson(flags, problem, command) {
  try {
    // flags.json を読み込み
    let flagsData = { contest: '', updated_at: '', flags: [] };
    if (fs.existsSync(FLAGS_FILE)) {
      try {
        flagsData = JSON.parse(fs.readFileSync(FLAGS_FILE, 'utf8'));
      } catch (e) {
        // パースエラーは無視
      }
    }

    // progress.json からコンテスト名を取得
    if (fs.existsSync(PROGRESS_FILE)) {
      try {
        const progress = JSON.parse(fs.readFileSync(PROGRESS_FILE, 'utf8'));
        flagsData.contest = progress.contest || flagsData.contest;
      } catch (e) {}
    }

    flagsData.updated_at = new Date().toISOString();

    // 各フラグを追加（重複チェック）
    for (const flag of flags) {
      const existing = flagsData.flags.find(f => f.flag === flag);
      if (!existing) {
        flagsData.flags.push({
          problem_id: problem?.id || null,
          problem_name: problem?.name || 'Unknown',
          category: problem?.category || detectCategoryFromCommand(command) || 'misc',
          points: problem?.points || 0,
          flag: flag,
          solved_at: new Date().toISOString(),
          method: extractMethod(command)
        });
        console.error(`📁 flags.json に保存: ${flag.substring(0, 30)}...`);
      }
    }

    // ctf_workspaceディレクトリがなければ作成
    if (!fs.existsSync(CTF_DIR)) {
      fs.mkdirSync(CTF_DIR, { recursive: true });
    }

    fs.writeFileSync(FLAGS_FILE, JSON.stringify(flagsData, null, 2));
  } catch (e) {
    console.error(`⚠️ flags.json 保存エラー: ${e.message}`);
  }
}

/**
 * 📄 FLAG.txt を問題ディレクトリに保存
 */
function saveFlagTxt(flags, problem) {
  if (!problem?.category || !problem?.name) return;

  try {
    // 問題名をディレクトリ名に変換（例: "Lv.40 022" -> "lv40_022"）
    const dirName = problem.name.toLowerCase().replace(/\./g, '').replace(/\s+/g, '_');
    const category = problem.category.toLowerCase();
    const problemDir = path.join(SOLUTIONS_DIR, category, dirName);

    // ディレクトリが存在しなければ作成
    if (!fs.existsSync(problemDir)) {
      fs.mkdirSync(problemDir, { recursive: true });
    }

    const flagFile = path.join(problemDir, 'FLAG.txt');
    fs.writeFileSync(flagFile, flags[0] + '\n');
    console.error(`📄 FLAG.txt 保存: ${flagFile}`);
  } catch (e) {
    console.error(`⚠️ FLAG.txt 保存エラー: ${e.message}`);
  }
}

/**
 * コマンドから解法を抽出
 */
function extractMethod(command) {
  if (!command) return '手動発見';

  if (/strings.*grep/i.test(command)) return 'stringsでフラグ抽出';
  if (/base64\s+-d/i.test(command)) return 'Base64デコード';
  if (/sqlmap/i.test(command)) return 'SQLインジェクション';
  if (/binwalk/i.test(command)) return 'binwalkでファイル抽出';
  if (/exiftool/i.test(command)) return 'EXIFメタデータ解析';
  if (/zsteg|steghide/i.test(command)) return 'ステガノグラフィ解析';
  if (/john|hashcat/i.test(command)) return 'パスワードクラック';
  if (/curl/i.test(command)) return 'HTTPリクエスト';
  if (/tshark|wireshark/i.test(command)) return 'パケット解析';
  if (/gdb|radare2/i.test(command)) return 'バイナリ解析';

  return command.split(' ')[0]; // コマンド名を返す
}

/**
 * 🧠 即時学習: フラグ検出時にinstincts.jsonとpatterns/*.mdを更新
 * 両方の場所（グローバル + プロジェクト）に保存
 * @returns {number} 学習したパターン数
 */
function learnImmediately(problem, successCommand) {
  let learnedCount = 0;
  const category = problem?.category || detectCategoryFromCommand(successCommand) || 'misc';

  // グローバルとプロジェクト両方のinstincts.jsonを更新
  const locations = [
    { dir: GLOBAL_LEARNING_DIR, file: GLOBAL_INSTINCTS_FILE, patterns: GLOBAL_PATTERNS_DIR },
    { dir: PROJECT_LEARNING_DIR, file: PROJECT_INSTINCTS_FILE, patterns: PROJECT_PATTERNS_DIR }
  ];

  for (const loc of locations) {
    // instincts.jsonを読み込み
    let instincts = { instincts: [], negative_patterns: [], contest_patterns: {} };
    if (fs.existsSync(loc.file)) {
      try {
        instincts = JSON.parse(fs.readFileSync(loc.file, 'utf8'));
      } catch (e) {
        // パースエラーは無視
      }
    }

    // 成功したコマンドからパターンを抽出
    const commands = problem?.commands || [successCommand];
    for (const cmd of commands) {
      const cmdStr = typeof cmd === 'string' ? cmd : cmd.command;
      if (!cmdStr) continue;

      for (const matcher of PATTERN_MATCHERS) {
        if (matcher.regex.test(cmdStr)) {
          const updated = updateInstinct(instincts, {
            trigger: matcher.trigger,
            action: matcher.action,
            category: category
          });
          if (updated && loc.dir === GLOBAL_LEARNING_DIR) learnedCount++;
          break;
        }
      }
    }

    // instincts.jsonを保存
    try {
      if (!fs.existsSync(loc.dir)) {
        fs.mkdirSync(loc.dir, { recursive: true });
      }
      fs.writeFileSync(loc.file, JSON.stringify(instincts, null, 2));
    } catch (e) {
      // 保存失敗は無視
    }

    // patterns/[category].mdに追記
    appendToPatternFile(loc.patterns, category, problem, successCommand);
  }

  return learnedCount;
}

/**
 * コマンドからカテゴリを推定
 */
function detectCategoryFromCommand(command) {
  if (!command) return null;

  if (/sqlmap|curl|gobuster|ffuf|burp|nikto|jwt/i.test(command)) return 'web';
  if (/base64|openssl|sage|factordb|xor|aes|rsa/i.test(command)) return 'crypto';
  if (/binwalk|exiftool|zsteg|steghide|volatility|foremost|strings/i.test(command)) return 'forensics';
  if (/gdb|checksec|pwntools|ROPgadget|one_gadget|objdump/i.test(command)) return 'pwn';
  if (/sherlock|holehe|whois|nslookup|exif/i.test(command)) return 'osint';

  return null;
}

/**
 * instinctを更新（既存があれば信頼度UP、なければ追加）
 * @returns {boolean} 新規追加または更新があった場合true
 */
function updateInstinct(instincts, newPattern) {
  const existing = instincts.instincts.find(
    i => i.trigger === newPattern.trigger && i.category === newPattern.category
  );

  if (existing) {
    // 既存パターン: 信頼度と使用回数を更新
    existing.source_count = (existing.source_count || 0) + 1;
    existing.confidence = Math.min(0.99, (existing.confidence || 0.5) + 0.03);
    existing.last_used = new Date().toISOString();
    return true;
  } else {
    // 新規パターン
    instincts.instincts.push({
      trigger: newPattern.trigger,
      action: newPattern.action,
      category: newPattern.category,
      confidence: 0.65,
      source_count: 1,
      first_seen: new Date().toISOString(),
      last_used: new Date().toISOString()
    });
    return true;
  }
}

/**
 * patterns/[category].mdに解法を追記 - 廃止
 * コンテキスト節約のため、patterns/*.md への自動追記を無効化
 * instincts.json のみで学習データを管理する
 * @param {string} patternsDir - patternsディレクトリのパス（未使用）
 */
function appendToPatternFile(patternsDir, category, problem, command) {
  // patterns/*.md への自動追記を廃止（コンテキスト節約）
  // 手動でレビュー・整理したい場合は別途スクリプトで生成
  return;
}

/**
 * 📚 学習データを ~/.claude/rules/ctf-learned.md に同期
 * 高信頼度パターンを新しいセッションでも即座に参照できるようにする
 */
function syncToRulesFile() {
  const RULES_DIR = path.join(os.homedir(), '.claude', 'rules');
  const LEARNED_RULES_FILE = path.join(RULES_DIR, 'ctf-learned.md');
  const CONFIDENCE_THRESHOLD = 0.70;
  const MIN_SOURCE_COUNT = 2;

  if (!fs.existsSync(GLOBAL_INSTINCTS_FILE)) return;

  try {
    const instincts = JSON.parse(fs.readFileSync(GLOBAL_INSTINCTS_FILE, 'utf8'));

    // 高信頼度パターンをフィルタ
    const highConfidencePatterns = instincts.instincts.filter(
      i => i.confidence >= CONFIDENCE_THRESHOLD && (i.source_count || 0) >= MIN_SOURCE_COUNT
    );

    if (highConfidencePatterns.length === 0) return;

    // カテゴリ別に分類
    const byCategory = {};
    for (const p of highConfidencePatterns) {
      const cat = p.category || 'misc';
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push(p);
    }

    // ルールファイルを生成
    let content = `# CTF 学習済みパターン（自動生成）

> 問題を解くたびに自動更新。信頼度 ${CONFIDENCE_THRESHOLD * 100}%以上、${MIN_SOURCE_COUNT}回以上使用されたパターン。
> 最終更新: ${new Date().toISOString()}

## 即座に試すべきパターン

`;

    for (const [category, patterns] of Object.entries(byCategory)) {
      content += `### ${category.toUpperCase()}\n`;
      patterns.sort((a, b) => b.confidence - a.confidence);
      for (const p of patterns) {
        content += `- **${p.trigger}** → ${p.action} (${Math.round(p.confidence * 100)}%)\n`;
      }
      content += '\n';
    }

    // 統計
    content += `## 統計\n- 総パターン: ${instincts.instincts.length} / 高信頼度: ${highConfidencePatterns.length}\n`;

    if (!fs.existsSync(RULES_DIR)) {
      fs.mkdirSync(RULES_DIR, { recursive: true });
    }
    fs.writeFileSync(LEARNED_RULES_FILE, content);
    console.error(`📚 ルール同期: ${highConfidencePatterns.length}パターン`);

  } catch (e) {
    // 同期失敗は無視
  }
}
