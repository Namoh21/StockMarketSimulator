import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, 'test-trading.db');

// Point db.js at a throwaway database before importing anything that loads it.
for (const ext of ['', '-wal', '-shm']) { try { fs.unlinkSync(DB_PATH + ext); } catch {} }
process.env.DB_PATH = DB_PATH;

const db = (await import('./db.js')).default;
const { applyFill, pendingReserved, pendingSellShares, availableCash, validTotal } = await import('./trading.js');

const USER_ID = 1;
const GAME_ID = 1;

before(() => {
  db.prepare("INSERT INTO users (id, username, email, password_hash, is_approved) VALUES (?, 'tester', 'tester@example.com', 'x', 1)").run(USER_ID);
  db.prepare("INSERT INTO game_config (id, start_date, end_date) VALUES (?, '2020-01-01', '2099-01-01')").run(GAME_ID);
  db.prepare('INSERT INTO portfolios (user_id, game_id, cash_balance) VALUES (?, ?, ?)').run(USER_ID, GAME_ID, 1000);
});

after(() => {
  db.close();
  for (const ext of ['', '-wal', '-shm']) { try { fs.unlinkSync(DB_PATH + ext); } catch {} }
});

test('validTotal rejects non-finite and negative values', () => {
  assert.equal(validTotal(100), true);
  assert.equal(validTotal(0), true);
  assert.equal(validTotal(-1), false);
  assert.equal(validTotal(NaN), false);
  assert.equal(validTotal(Infinity), false);
});

test('applyFill buy: success deducts cash and creates holding', () => {
  const total = applyFill(USER_ID, GAME_ID, 'AAPL', 'Apple Inc.', 'buy', 2, 100);
  assert.equal(total, 200);
  const p = db.prepare('SELECT cash_balance FROM portfolios WHERE user_id=? AND game_id=?').get(USER_ID, GAME_ID);
  assert.equal(p.cash_balance, 800);
  const h = db.prepare('SELECT * FROM holdings WHERE user_id=? AND game_id=? AND symbol=?').get(USER_ID, GAME_ID, 'AAPL');
  assert.equal(h.shares, 2);
  assert.equal(h.avg_cost, 100);
});

test('applyFill buy: rejects when insufficient funds', () => {
  assert.throws(() => applyFill(USER_ID, GAME_ID, 'AAPL', 'Apple Inc.', 'buy', 1000, 100), /Insufficient funds/);
  const p = db.prepare('SELECT cash_balance FROM portfolios WHERE user_id=? AND game_id=?').get(USER_ID, GAME_ID);
  assert.equal(p.cash_balance, 800); // unchanged
});

test('applyFill buy: averages cost on additional purchase', () => {
  applyFill(USER_ID, GAME_ID, 'AAPL', 'Apple Inc.', 'buy', 2, 200);
  const h = db.prepare('SELECT * FROM holdings WHERE user_id=? AND game_id=? AND symbol=?').get(USER_ID, GAME_ID, 'AAPL');
  assert.equal(h.shares, 4);
  assert.equal(h.avg_cost, 150); // (2*100 + 2*200) / 4
});

test('applyFill sell: success returns cash and reduces shares', () => {
  const total = applyFill(USER_ID, GAME_ID, 'AAPL', 'Apple Inc.', 'sell', 1, 150);
  assert.equal(total, 150);
  const h = db.prepare('SELECT * FROM holdings WHERE user_id=? AND game_id=? AND symbol=?').get(USER_ID, GAME_ID, 'AAPL');
  assert.equal(h.shares, 3);
});

test('applyFill sell: rejects selling more shares than held (no double-sell)', () => {
  assert.throws(() => applyFill(USER_ID, GAME_ID, 'AAPL', 'Apple Inc.', 'sell', 100, 150), /Insufficient shares/);
  const h = db.prepare('SELECT * FROM holdings WHERE user_id=? AND game_id=? AND symbol=?').get(USER_ID, GAME_ID, 'AAPL');
  assert.equal(h.shares, 3); // unchanged
});

test('pendingReserved sums only pending buy orders for the user/game', () => {
  db.prepare(`INSERT INTO pending_orders (user_id, game_id, symbol, type, order_type, shares, status, reserved_amount)
              VALUES (?, ?, 'MSFT', 'buy', 'limit', 1, 'pending', 250)`).run(USER_ID, GAME_ID);
  db.prepare(`INSERT INTO pending_orders (user_id, game_id, symbol, type, order_type, shares, status, reserved_amount)
              VALUES (?, ?, 'MSFT', 'buy', 'limit', 1, 'filled', 999)`).run(USER_ID, GAME_ID);
  assert.equal(pendingReserved(USER_ID, GAME_ID), 250);
});

test('pendingSellShares sums only pending sell orders for the symbol', () => {
  db.prepare(`INSERT INTO pending_orders (user_id, game_id, symbol, type, order_type, shares, status, reserved_amount)
              VALUES (?, ?, 'AAPL', 'sell', 'limit', 1.5, 'pending', 0)`).run(USER_ID, GAME_ID);
  assert.equal(pendingSellShares(USER_ID, GAME_ID, 'AAPL'), 1.5);
  assert.equal(pendingSellShares(USER_ID, GAME_ID, 'MSFT'), 0);
});

test('availableCash subtracts pending reserved cash from balance', () => {
  const p = db.prepare('SELECT cash_balance FROM portfolios WHERE user_id=? AND game_id=?').get(USER_ID, GAME_ID);
  const expected = Math.max(0, p.cash_balance - 250);
  assert.equal(availableCash(USER_ID, GAME_ID), expected);
});
