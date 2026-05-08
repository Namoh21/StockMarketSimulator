import nodemailer from 'nodemailer';

// ── Mutable transport — reconfigured at runtime via configureMailer() ─────────
let _mailer  = null;
let _from    = 'StockArena <noreply@stockarena.local>';
let _baseUrl = 'http://localhost:8081';

/** Call at startup (and after admin saves settings) to (re)init the transporter. */
export async function configureMailer({ host, port, user, pass, from, baseUrl } = {}) {
  if (from)    _from    = from;
  if (baseUrl) _baseUrl = baseUrl.replace(/\/$/, '');

  if (host && user && pass) {
    _mailer = nodemailer.createTransport({
      host,
      port:   +(port || 587),
      secure: +(port || 587) === 465,
      auth:   { user, pass },
    });
    try {
      await _mailer.verify();
      console.log('  ✉  Email relay connected and ready');
      return { ok: true };
    } catch (err) {
      console.warn('  ⚠  Email relay unreachable:', err.message);
      _mailer = null;
      return { ok: false, error: err.message };
    }
  }
  _mailer = null;
  return { ok: false, error: 'SMTP not configured' };
}

export function isEmailEnabled() { return !!_mailer; }

export async function sendEmail(to, subject, html) {
  if (!_mailer || !to || to.endsWith('@local')) return false;
  try {
    await _mailer.sendMail({ from: _from, to, subject, html });
    console.log(`[Email] Sent "${subject}" → ${to}`);
    return true;
  } catch (err) {
    console.error(`[Email] "${subject}" → ${to} FAILED: ${err.message}`);
    return false;
  }
}

// ── Shared layout ─────────────────────────────────────────────────────────────
function getBaseUrl() { return _baseUrl; }

function layout(title, body) {
  const BASE_URL = _baseUrl;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head>
<body style="margin:0;padding:0;background:#0f172a;font-family:system-ui,-apple-system,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:540px">
<tr><td style="background:#1e293b;border-radius:12px;padding:28px 30px;border:1px solid #334155">

  <div style="border-bottom:1px solid #334155;padding-bottom:14px;margin-bottom:22px">
    <span style="font-size:20px;font-weight:800;color:#f59e0b">📈 StockArena</span>
    <span style="font-size:11px;color:#64748b;margin-left:10px">Real stocks · Simulated money</span>
  </div>

  ${body}

  <div style="border-top:1px solid #334155;margin-top:24px;padding-top:14px;font-size:11px;color:#475569;line-height:1.6">
    You're receiving this because you enabled notifications in StockArena.<br>
    To change your preferences, visit
    <a href="${BASE_URL}" style="color:#3b82f6;text-decoration:none">StockArena</a>
    → Notifications tab.
  </div>
</td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function fmt(n) { return '$' + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
function fmtShares(n) { return n % 1 === 0 ? n.toLocaleString() : Number(n).toFixed(4).replace(/\.?0+$/, ''); }

// ── Trade confirmation ────────────────────────────────────────────────────────
export function buildTradeEmail({ username, gameName, type, symbol, companyName, shares, price, total, cashBalance }) {
  const isBuy    = type === 'buy';
  const accentBg = isBuy ? '#14532d' : '#7f1d1d';
  const accent   = isBuy ? '#22c55e' : '#ef4444';
  const verb     = isBuy ? 'BOUGHT' : 'SOLD';

  return layout(`${verb} ${fmtShares(shares)} × ${symbol} — StockArena`, `
    <div style="background:${accentBg};border-radius:8px;padding:14px 16px;margin-bottom:20px;border:1px solid ${accent}">
      <div style="color:${accent};font-size:17px;font-weight:800">${isBuy ? '▲' : '▼'} ${verb} ${fmtShares(shares)} share${shares !== 1 ? 's' : ''} of ${symbol}</div>
      <div style="color:#94a3b8;font-size:12px;margin-top:3px">${companyName || symbol} · ${gameName}</div>
    </div>

    <p style="margin:0 0 16px;color:#94a3b8;font-size:13px">Hi <strong style="color:#e2e8f0">${username}</strong>, your order has been filled.</p>

    <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;border-radius:6px;overflow:hidden">
      <tr style="background:#0f172a">
        <td style="padding:9px 10px;color:#94a3b8">Fill Price</td>
        <td style="padding:9px 10px;text-align:right;font-weight:600">${fmt(price)}</td>
      </tr>
      <tr>
        <td style="padding:9px 10px;color:#94a3b8">Shares</td>
        <td style="padding:9px 10px;text-align:right;font-weight:600">${fmtShares(shares)}</td>
      </tr>
      <tr style="background:#0f172a">
        <td style="padding:9px 10px;color:#94a3b8">${isBuy ? 'Total Cost' : 'Proceeds'}</td>
        <td style="padding:9px 10px;text-align:right;font-weight:600;color:${accent}">${isBuy ? '−' : '+'}${fmt(total)}</td>
      </tr>
      <tr style="border-top:1px solid #334155">
        <td style="padding:11px 10px;font-weight:700">New Cash Balance</td>
        <td style="padding:11px 10px;text-align:right;font-weight:800;font-size:16px;color:#f59e0b">${fmt(cashBalance)}</td>
      </tr>
    </table>

    <div style="margin-top:18px;text-align:center">
      <a href="${BASE_URL}" style="display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:10px 22px;border-radius:6px;font-weight:600;font-size:13px">View Portfolio →</a>
    </div>
  `);
}

// ── Daily summary ─────────────────────────────────────────────────────────────
export function buildDailySummaryEmail({ username, date, games }) {
  // games: array of { gameName, totalValue, startingCash, cashBalance, stockValue, futuresPnl, rank, totalPlayers, holdings }

  const gameSections = games.map(g => {
    const gain    = g.totalValue - g.startingCash;
    const gainPct = (gain / g.startingCash * 100).toFixed(2);
    const gainColor = gain >= 0 ? '#22c55e' : '#ef4444';
    const rankEmoji = g.rank === 1 ? '🥇' : g.rank === 2 ? '🥈' : g.rank === 3 ? '🥉' : `#${g.rank}`;

    const holdingRows = g.holdings.length
      ? g.holdings.map(h => {
          const pnl = (h.current_price - h.avg_cost) * h.shares;
          const pc  = gain >= 0 ? '#22c55e' : '#ef4444';
          return `<tr>
            <td style="padding:6px 8px;font-weight:600">${h.symbol}</td>
            <td style="padding:6px 8px;color:#94a3b8;font-size:12px">${fmtShares(h.shares)} sh</td>
            <td style="padding:6px 8px;text-align:right">${fmt(h.current_price)}</td>
            <td style="padding:6px 8px;text-align:right;color:${pnl >= 0 ? '#22c55e' : '#ef4444'};font-weight:600">${pnl >= 0 ? '+' : ''}${fmt(pnl)}</td>
          </tr>`;
        }).join('')
      : `<tr><td colspan="4" style="padding:12px;color:#475569;text-align:center">No holdings</td></tr>`;

    return `
      <div style="background:#0f172a;border-radius:8px;padding:14px 16px;margin-bottom:14px">
        <div style="font-weight:700;font-size:15px;margin-bottom:10px;color:#e2e8f0">${g.gameName}</div>

        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;margin-bottom:10px">
          <tr>
            <td style="padding:4px 0;color:#94a3b8">Total Value</td>
            <td style="padding:4px 0;text-align:right;font-weight:800;font-size:16px">${fmt(g.totalValue)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#94a3b8">Gain / Loss</td>
            <td style="padding:4px 0;text-align:right;font-weight:700;color:${gainColor}">${gain >= 0 ? '+' : ''}${fmt(gain)} (${gain >= 0 ? '+' : ''}${gainPct}%)</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#94a3b8">Cash</td>
            <td style="padding:4px 0;text-align:right">${fmt(g.cashBalance)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#94a3b8">Rank</td>
            <td style="padding:4px 0;text-align:right;font-weight:700">${rankEmoji} of ${g.totalPlayers} players</td>
          </tr>
        </table>

        <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Holdings</div>
        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:12px">
          <tr style="border-bottom:1px solid #1e293b">
            <th style="text-align:left;padding:4px 8px;color:#475569;font-weight:500">Symbol</th>
            <th style="text-align:left;padding:4px 8px;color:#475569;font-weight:500">Shares</th>
            <th style="text-align:right;padding:4px 8px;color:#475569;font-weight:500">Price</th>
            <th style="text-align:right;padding:4px 8px;color:#475569;font-weight:500">P&amp;L</th>
          </tr>
          ${holdingRows}
        </table>
      </div>`;
  }).join('');

  return layout(`Daily Summary — ${date} — StockArena`, `
    <p style="margin:0 0 18px;color:#94a3b8;font-size:13px">
      Hi <strong style="color:#e2e8f0">${username}</strong>, here's your end-of-day portfolio summary for <strong>${date}</strong>.
    </p>
    ${gameSections}
    <div style="margin-top:10px;text-align:center">
      <a href="${BASE_URL}" style="display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:10px 22px;border-radius:6px;font-weight:600;font-size:13px">Open StockArena →</a>
    </div>
  `);
}

// ── Ranking alert ─────────────────────────────────────────────────────────────
export function buildRankingEmail({ username, gameName, rank, totalPlayers, totalValue, gain, gainPct }) {
  const gainColor = gain >= 0 ? '#22c55e' : '#ef4444';
  const rankEmoji = rank === 1 ? '🥇' : rank === 2 ? '🥈' : rank === 3 ? '🥉' : '';

  return layout(`You're ranked #${rank} in ${gameName} — StockArena`, `
    <p style="margin:0 0 18px;color:#94a3b8;font-size:13px">Hi <strong style="color:#e2e8f0">${username}</strong>, here's a ranking update for <strong>${gameName}</strong>.</p>

    <div style="background:#0f172a;border-radius:10px;padding:20px;text-align:center;margin-bottom:20px">
      <div style="font-size:13px;color:#64748b;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">Your Rank</div>
      <div style="font-size:48px;font-weight:900;color:#f59e0b">${rankEmoji || '#' + rank}</div>
      <div style="color:#94a3b8;font-size:13px;margin-top:4px">out of ${totalPlayers} players</div>
    </div>

    <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px">
      <tr style="background:#0f172a">
        <td style="padding:10px;color:#94a3b8">Portfolio Value</td>
        <td style="padding:10px;text-align:right;font-weight:800;font-size:15px">${fmt(totalValue)}</td>
      </tr>
      <tr>
        <td style="padding:10px;color:#94a3b8">Total Gain / Loss</td>
        <td style="padding:10px;text-align:right;font-weight:700;color:${gainColor}">${gain >= 0 ? '+' : ''}${fmt(gain)} (${gain >= 0 ? '+' : ''}${gainPct.toFixed(2)}%)</td>
      </tr>
    </table>

    <div style="margin-top:18px;text-align:center">
      <a href="${BASE_URL}" style="display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:10px 22px;border-radius:6px;font-weight:600;font-size:13px">View Leaderboard →</a>
    </div>
  `);
}

// ── Test email ────────────────────────────────────────────────────────────────
export function buildTestEmail(username) {
  return layout('Test Email — StockArena', `
    <div style="text-align:center;padding:20px 0">
      <div style="font-size:48px;margin-bottom:12px">✅</div>
      <div style="font-size:18px;font-weight:700;margin-bottom:8px">Email notifications are working!</div>
      <p style="color:#94a3b8;font-size:13px;margin:0">Hi ${username}, you'll receive emails based on your notification settings.</p>
    </div>
  `);
}
