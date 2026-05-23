#!/usr/bin/env node
// ============================================================
//  StockArena — Admin Password Reset
//  Run from the project directory on the Raspberry Pi:
//
//    node reset-password.js
//    node reset-password.js <username>          # target a specific user
//    node reset-password.js <username> <newpw>  # non-interactive
// ============================================================
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createInterface } from 'readline';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database(path.join(__dirname, 'stockgame.db'));
db.pragma('foreign_keys = ON');

const R = '\x1b[31m', G = '\x1b[32m', Y = '\x1b[33m', B = '\x1b[34m', N = '\x1b[0m', BOLD = '\x1b[1m';

function ask(prompt) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(prompt, ans => { rl.close(); resolve(ans.trim()); }));
}

function askHidden(prompt) {
  return new Promise(resolve => {
    process.stdout.write(prompt);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    let pw = '';
    process.stdin.on('data', function handler(ch) {
      if (ch === '\r' || ch === '\n') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener('data', handler);
        process.stdout.write('\n');
        resolve(pw);
      } else if (ch === '') { // Ctrl-C
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write('\n');
        process.exit(1);
      } else if (ch === '') { // Backspace
        if (pw.length) { pw = pw.slice(0, -1); process.stdout.write('\b \b'); }
      } else {
        pw += ch;
        process.stdout.write('*');
      }
    });
  });
}

console.log(`\n${BOLD}  ╔══════════════════════════════════════════╗`);
console.log(`  ║   🔑  StockArena Password Reset          ║`);
console.log(`  ╚══════════════════════════════════════════╝${N}\n`);

const admins = db.prepare('SELECT id, username, is_admin FROM users WHERE is_admin = 1').all();
const all    = db.prepare('SELECT id, username, is_admin FROM users ORDER BY id').all();

if (!all.length) {
  console.error(`${R}No users found in the database.${N}`);
  process.exit(1);
}

console.log(`${B}Users in database:${N}`);
for (const u of all) {
  console.log(`  ${u.id.toString().padStart(3)}  ${u.username.padEnd(24)} ${u.is_admin ? `${Y}[ADMIN]${N}` : ''}`);
}
console.log('');

// Resolve username — from CLI arg, or prompt
let targetUsername = process.argv[2];
if (!targetUsername) {
  const defaultUser = admins[0]?.username || all[0].username;
  targetUsername = await ask(`${BOLD}Username to reset${N} [${defaultUser}]: `);
  if (!targetUsername) targetUsername = defaultUser;
}

const target = all.find(u => u.username.toLowerCase() === targetUsername.toLowerCase());
if (!target) {
  console.error(`${R}User "${targetUsername}" not found.${N}`);
  process.exit(1);
}

console.log(`\nResetting password for ${BOLD}${target.username}${N}${target.is_admin ? ` ${Y}(admin)${N}` : ''}\n`);

// Resolve new password — from CLI arg, or prompt (hidden input)
let newPassword = process.argv[3];
if (!newPassword) {
  newPassword = await askHidden(`${BOLD}New password${N}: `);
  if (newPassword.length < 6) {
    console.error(`${R}Password must be at least 6 characters.${N}`);
    process.exit(1);
  }
  const confirm = await askHidden(`${BOLD}Confirm password${N}: `);
  if (newPassword !== confirm) {
    console.error(`${R}Passwords do not match.${N}`);
    process.exit(1);
  }
} else if (newPassword.length < 6) {
  console.error(`${R}Password must be at least 6 characters.${N}`);
  process.exit(1);
}

process.stdout.write('Hashing password… ');
const hash = await bcrypt.hash(newPassword, 10);
db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, target.id);
console.log(`${G}done${N}`);

// Also approve the account in case it got locked
db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').run(target.id);

console.log(`\n${BOLD}${G}✅  Password updated for "${target.username}"${N}`);
console.log(`   Account is also marked approved.\n`);

db.close();
