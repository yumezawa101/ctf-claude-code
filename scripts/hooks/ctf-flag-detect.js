#!/usr/bin/env node
/**
 * Bash出力からフラグパターンを検出し、自動記録・学習する
 * パターン: FLAG{...}, flag{...}, ctf{...}, [大会名]{...}
 */
const fs = require('fs');
const path = require('path');

const CTF_DIR = path.join(process.cwd(), '.ctf');
const PROGRESS_FILE = path.join(CTF_DIR, 'progress.json');
const COMMAND_LOG_FILE = path.join(CTF_DIR, 'command-log.json');

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
      console.error('='.repeat(50) + '\n');

      // progress.jsonを更新
      updateProgress(flags, command);
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

  // .ctfディレクトリがなければ作成
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
 */
function updateProgress(flags, command) {
  if (!fs.existsSync(PROGRESS_FILE)) return;

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
  } catch (e) {
    // エラーは無視
  }
}
