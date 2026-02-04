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

    // コマンドを記録（学習用）
    recordCommand(command, output);

    // フラグパターンを検索
    const foundFlags = new Set();

    for (const pattern of FLAG_PATTERNS) {
      const matches = output.match(pattern);
      if (matches) {
        matches.forEach(flag => foundFlags.add(flag));
      }
    }

    // フラグが見つかった場合
    if (foundFlags.size > 0) {
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

      // 🧠 即時学習: instincts.json と patterns/*.md を更新
      const learnedPatterns = learnImmediately(problem, command);
      if (learnedPatterns > 0) {
        console.error(`\n🧠 学習完了: ${learnedPatterns}個のパターンを記録`);
      }

      // 📚 学習データをルールファイルに同期
      syncToRulesFile();

      console.error('='.repeat(50) + '\n');
    }

    // 入力をそのまま出力（パススルー）
    console.log(input);
  } catch (e) {
    // JSONパースエラー時はそのまま出力
    console.log(input);
  }
});

/**
 * コマンドを記録（学習用）
 */
function recordCommand(command, output) {
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

  // 最新100コマンドのみ保持
  commandLog.commands.push({
    command: command,
    timestamp: new Date().toISOString(),
    output_length: output.length,
    has_flag: FLAG_PATTERNS.some(p => p.test(output))
  });

  if (commandLog.commands.length > 100) {
    commandLog.commands = commandLog.commands.slice(-100);
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
 * patterns/[category].mdに解法を追記
 * @param {string} patternsDir - patternsディレクトリのパス
 */
function appendToPatternFile(patternsDir, category, problem, command) {
  const patternFile = path.join(patternsDir, `${category}.md`);

  try {
    if (!fs.existsSync(patternsDir)) {
      fs.mkdirSync(patternsDir, { recursive: true });
    }

    const problemName = problem?.name || 'Unknown';
    const flag = problem?.flag || '';
    const timestamp = new Date().toISOString().split('T')[0];

    // 追記内容を作成
    const entry = `
### ${problemName} (${timestamp})
- **Flag**: \`${flag.substring(0, 20)}...\`
- **成功コマンド**: \`${command?.substring(0, 100) || 'N/A'}\`
- **学習ポイント**: このパターンが有効だった

`;

    // ファイルが存在しない場合はヘッダーを追加
    if (!fs.existsSync(patternFile)) {
      const header = `# ${category.toUpperCase()} パターン集

このファイルは問題を解くたびに自動更新されます。

---
`;
      fs.writeFileSync(patternFile, header + entry);
    } else {
      fs.appendFileSync(patternFile, entry);
    }
  } catch (e) {
    // 追記失敗は無視
  }
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
