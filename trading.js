// Core money/share movement logic — kept separate from server.js so it can be
// unit-tested without booting the HTTP server or background jobs.
import db from './db.js';

export function validTotal(n) { return Number.isFinite(n) && n >= 0; } // guards against NaN/Infinity in price×shares

// Sum of cash held by pending buy orders — these funds are reserved and unavailable.
export function pendingReserved(userId, gameId) {
  return db.prepare(
    "SELECT COALESCE(SUM(reserved_amount),0) as total FROM pending_orders WHERE user_id=? AND game_id=? AND type='buy' AND status='pending'"
  ).get(userId, gameId)?.total ?? 0;
}

// Shares of a symbol already committed to pending sell orders — can't be sold twice.
export function pendingSellShares(userId, gameId, symbol) {
  return db.prepare(
    "SELECT COALESCE(SUM(shares),0) as total FROM pending_orders WHERE user_id=? AND game_id=? AND symbol=? AND type='sell' AND status='pending'"
  ).get(userId, gameId, symbol)?.total ?? 0;
}

// Cash the user can actually spend: balance minus anything locked in pending buys.
export function availableCash(userId, gameId, portfolio = null) {
  const p = portfolio ?? db.prepare('SELECT cash_balance FROM portfolios WHERE user_id=? AND game_id=?').get(userId, gameId);
  return Math.max(0, (p?.cash_balance ?? 0) - pendingReserved(userId, gameId));
}

// ── Core fill logic (shared by immediate trades and background processor) ─────
export function applyFill(userId, gameId, symbol, companyName, type, shares, price) {
  const total = +(price * shares).toFixed(6);
  if (!validTotal(total)) throw new Error('Invalid trade total — numeric overflow or NaN');
  db.transaction(() => {
    if (type === 'buy') {
      // Atomic conditional deduct — WHERE cash_balance >= total guarantees no overdraft
      // even under concurrent requests or stale pre-checks.
      const result = db.prepare(
        'UPDATE portfolios SET cash_balance = cash_balance - ? WHERE user_id = ? AND game_id = ? AND cash_balance >= ?'
      ).run(total, userId, gameId, total);
      if (result.changes === 0) throw new Error(`Insufficient funds — need $${total.toFixed(2)}`);
      const ex = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(userId, gameId, symbol);
      if (ex) {
        const ns = ex.shares + shares;
        db.prepare('UPDATE holdings SET shares=?, avg_cost=?, company_name=? WHERE id=?')
          .run(ns, (ex.avg_cost * ex.shares + price * shares) / ns, companyName, ex.id);
      } else {
        db.prepare('INSERT INTO holdings (user_id,game_id,symbol,company_name,shares,avg_cost) VALUES (?,?,?,?,?,?)').run(userId, gameId, symbol, companyName, shares, price);
      }
    } else {
      // Atomic conditional deduct — WHERE shares >= requested guarantees the same
      // shares can't be sold twice under concurrent requests or stale pre-checks.
      const result = db.prepare(
        `UPDATE holdings SET shares = CASE WHEN shares - ? < 0.000001 THEN 0 ELSE shares - ? END
         WHERE user_id = ? AND game_id = ? AND symbol = ? AND shares >= ? - 0.000001`
      ).run(shares, shares, userId, gameId, symbol, shares);
      if (result.changes === 0) throw new Error(`Insufficient shares of ${symbol}`);
      db.prepare('UPDATE portfolios SET cash_balance = cash_balance + ? WHERE user_id = ? AND game_id = ?').run(total, userId, gameId);
    }
    db.prepare('INSERT INTO transactions (user_id,game_id,symbol,company_name,type,shares,price,total) VALUES (?,?,?,?,?,?,?,?)')
      .run(userId, gameId, symbol, companyName, type, shares, price, total);
  })();
  return total;
}
