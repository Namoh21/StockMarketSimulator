import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import yf from 'yahoo-finance2';
import path from 'path';
import { fileURLToPath } from 'url';
import db from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 8081;
const JWT_SECRET = process.env.JWT_SECRET || 'stockarena-change-this-secret-in-production';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Suppress Yahoo Finance survey notices
try { yf.suppressNotices(['yahooSurvey']); } catch {}

// ── Price cache (5-min TTL) ──────────────────────────────────────────────────
const priceCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

async function getQuote(symbol) {
  const sym = symbol.toUpperCase();
  const cached = priceCache.get(sym);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached;

  const q = await yf.quote(sym, {}, { validateResult: false });
  if (!q || q.regularMarketPrice == null) throw new Error(`No price data for ${sym}`);

  const data = {
    symbol: q.symbol || sym,
    name: q.longName || q.shortName || sym,
    price: q.regularMarketPrice,
    open: q.regularMarketOpen || q.regularMarketPrice,
    high: q.regularMarketDayHigh || q.regularMarketPrice,
    low: q.regularMarketDayLow || q.regularMarketPrice,
    change: q.regularMarketChange || 0,
    changePercent: q.regularMarketChangePercent || 0,
    volume: q.regularMarketVolume || 0,
    marketCap: q.marketCap || null,
    exchange: q.exchange || '',
    marketState: q.marketState || 'CLOSED',
    timestamp: Date.now(),
  };
  priceCache.set(sym, data);
  return data;
}

// ── Exchange allow-list ───────────────────────────────────────────────────────
const MARKET_EXCHANGES = {
  NYSE:   ['NYQ', 'NYS', 'NYSEArca', 'NYSEAmex'],
  NASDAQ: ['NMS', 'NGM', 'NCM', 'NAS', 'NSQ'],
  AMEX:   ['ASE', 'AMX'],
};

function isExchangeAllowed(exchange, markets) {
  if (!markets || markets.includes('ALL')) return true;
  const allowed = markets.flatMap(m => MARKET_EXCHANGES[m] || []);
  return allowed.includes(exchange);
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function getActiveGame() {
  return db.prepare('SELECT * FROM game_config WHERE is_active = 1 ORDER BY id DESC LIMIT 1').get();
}

function ensurePortfolio(userId, gameId, startingCash) {
  const existing = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(userId, gameId);
  if (!existing) {
    db.prepare('INSERT INTO portfolios (user_id, game_id, cash_balance) VALUES (?, ?, ?)').run(userId, gameId, startingCash);
    return { cash_balance: startingCash };
  }
  return existing;
}

function gameStatus(game) {
  if (!game) return 'none';
  const now = new Date();
  if (now < new Date(game.start_date)) return 'pending';
  if (now > new Date(game.end_date)) return 'ended';
  return 'active';
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username?.trim() || !email?.trim() || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const isFirstUser = db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0;
    const { lastInsertRowid } = db.prepare(
      'INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)'
    ).run(username.trim(), email.trim().toLowerCase(), hash, isFirstUser ? 1 : 0);

    const user = db.prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?').get(lastInsertRowid);
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Username or email already taken' });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ═══════════════════════════════════════════════════════════════════════════════
// GAME CONFIG ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/game/config', (req, res) => {
  const game = db.prepare('SELECT * FROM game_config ORDER BY id DESC LIMIT 1').get();
  if (!game) return res.json(null);
  res.json({ ...game, markets: JSON.parse(game.markets), status: gameStatus(game) });
});

app.post('/api/game/config', requireAdmin, (req, res) => {
  const { title, start_date, end_date, starting_cash, markets, allow_fractional } = req.body || {};
  if (!start_date || !end_date || !starting_cash) {
    return res.status(400).json({ error: 'start_date, end_date, and starting_cash are required' });
  }
  if (new Date(end_date) <= new Date(start_date)) {
    return res.status(400).json({ error: 'end_date must be after start_date' });
  }
  if (starting_cash < 100) {
    return res.status(400).json({ error: 'starting_cash must be at least $100' });
  }

  db.prepare('UPDATE game_config SET is_active = 0').run();
  const { lastInsertRowid } = db.prepare(
    `INSERT INTO game_config (title, start_date, end_date, starting_cash, markets, allow_fractional, is_active)
     VALUES (?, ?, ?, ?, ?, ?, 1)`
  ).run(
    title?.trim() || 'Stock Trading Game',
    start_date,
    end_date,
    starting_cash,
    JSON.stringify(markets && markets.length ? markets : ['NYSE', 'NASDAQ']),
    allow_fractional ? 1 : 0
  );

  const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(lastInsertRowid);
  res.json({ ...game, markets: JSON.parse(game.markets), status: gameStatus(game) });
});

app.get('/api/game/leaderboard', requireAuth, async (req, res) => {
  const game = getActiveGame();
  if (!game) return res.json([]);

  const portfolios = db.prepare(
    'SELECT p.*, u.username FROM portfolios p JOIN users u ON p.user_id = u.id WHERE p.game_id = ?'
  ).all(game.id);

  const holdings = db.prepare('SELECT * FROM holdings WHERE game_id = ? AND shares > 0').all(game.id);
  const byUser = {};
  for (const h of holdings) {
    (byUser[h.user_id] = byUser[h.user_id] || []).push(h);
  }

  const symbols = [...new Set(holdings.map(h => h.symbol))];
  const prices = {};
  await Promise.allSettled(
    symbols.map(async s => {
      try { prices[s] = (await getQuote(s)).price; } catch { prices[s] = null; }
    })
  );

  const rows = portfolios.map(p => {
    const userHoldings = byUser[p.user_id] || [];
    const stockValue = userHoldings.reduce((sum, h) => sum + h.shares * (prices[h.symbol] ?? h.avg_cost), 0);
    const totalValue = p.cash_balance + stockValue;
    const gain = totalValue - game.starting_cash;
    return {
      username: p.username,
      cash_balance: p.cash_balance,
      stock_value: stockValue,
      total_value: totalValue,
      gain,
      gain_pct: (gain / game.starting_cash) * 100,
    };
  });

  rows.sort((a, b) => b.total_value - a.total_value);
  rows.forEach((r, i) => (r.rank = i + 1));
  res.json(rows);
});

app.get('/api/game/players', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at').all();
  res.json(users);
});

// ═══════════════════════════════════════════════════════════════════════════════
// STOCK ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/stocks/search', async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 1) return res.json([]);
  try {
    const results = await yf.search(q, { quotesCount: 12, newsCount: 0 }, { validateResult: false });
    const filtered = (results.quotes || [])
      .filter(r => r.quoteType === 'EQUITY' && r.symbol && !r.symbol.includes('.'))
      .slice(0, 8)
      .map(r => ({
        symbol: r.symbol,
        name: r.longname || r.shortname || r.symbol || r.dispSecIndFlag || '',
        exchange: r.exchange || '',
        type: r.quoteType,
      }));
    res.json(filtered);
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: 'Search failed: ' + err.message });
  }
});

app.get('/api/stocks/quote/:symbol', async (req, res) => {
  try {
    res.json(await getQuote(req.params.symbol));
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

app.get('/api/stocks/chart/:symbol', async (req, res) => {
  try {
    const symbol = req.params.symbol.toUpperCase();
    const period1 = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const result = await yf.chart(symbol, { period1, interval: '1d' }, { validateResult: false });
    const quotes = (result.quotes || [])
      .filter(q => q.close != null)
      .map(q => ({ date: q.date, close: q.close }));
    res.json(quotes);
  } catch (err) {
    res.json([]); // return empty on failure so chart just doesn't render
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PORTFOLIO & TRADE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/portfolio', requireAuth, async (req, res) => {
  const game = getActiveGame();
  if (!game) return res.json({ game: null, cash_balance: 0, stock_value: 0, total_value: 0, holdings: [] });

  const portfolio = ensurePortfolio(req.user.id, game.id, game.starting_cash);
  const holdings = db.prepare(
    'SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND shares > 0'
  ).all(req.user.id, game.id);

  const enriched = await Promise.all(holdings.map(async h => {
    try {
      const q = await getQuote(h.symbol);
      return {
        ...h,
        current_price: q.price,
        change: q.change,
        change_percent: q.changePercent,
        market_value: h.shares * q.price,
        gain_loss: (q.price - h.avg_cost) * h.shares,
        gain_loss_pct: ((q.price - h.avg_cost) / h.avg_cost) * 100,
      };
    } catch {
      return {
        ...h,
        current_price: h.avg_cost,
        change: 0, change_percent: 0,
        market_value: h.shares * h.avg_cost,
        gain_loss: 0, gain_loss_pct: 0,
      };
    }
  }));

  const stockValue = enriched.reduce((s, h) => s + h.market_value, 0);
  res.json({
    game: { ...game, markets: JSON.parse(game.markets), status: gameStatus(game) },
    cash_balance: portfolio.cash_balance,
    stock_value: stockValue,
    total_value: portfolio.cash_balance + stockValue,
    holdings: enriched,
  });
});

app.post('/api/trades/buy', requireAuth, async (req, res) => {
  let { symbol, shares } = req.body || {};
  symbol = symbol?.toUpperCase();
  shares = parseFloat(shares);

  if (!symbol || isNaN(shares) || shares <= 0) {
    return res.status(400).json({ error: 'symbol and positive shares are required' });
  }

  const game = getActiveGame();
  if (!game) return res.status(400).json({ error: 'No active game' });

  const status = gameStatus(game);
  if (status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });

  if (!game.allow_fractional && !Number.isInteger(shares)) {
    return res.status(400).json({ error: 'Fractional shares are not allowed in this game' });
  }

  let quote;
  try { quote = await getQuote(symbol); }
  catch (err) { return res.status(400).json({ error: err.message }); }

  const markets = JSON.parse(game.markets);
  if (!isExchangeAllowed(quote.exchange, markets)) {
    return res.status(400).json({
      error: `${symbol} trades on ${quote.exchange}, which is not in the allowed markets (${markets.join(', ')})`,
    });
  }

  const total = +(quote.price * shares).toFixed(6);
  const portfolio = ensurePortfolio(req.user.id, game.id, game.starting_cash);

  if (total > portfolio.cash_balance) {
    return res.status(400).json({
      error: `Insufficient funds — cost $${total.toFixed(2)}, available $${portfolio.cash_balance.toFixed(2)}`,
    });
  }

  db.transaction(() => {
    db.prepare('UPDATE portfolios SET cash_balance = cash_balance - ? WHERE user_id = ? AND game_id = ?')
      .run(total, req.user.id, game.id);

    const existing = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?')
      .get(req.user.id, game.id, symbol);

    if (existing) {
      const newShares = existing.shares + shares;
      const newAvg    = (existing.avg_cost * existing.shares + quote.price * shares) / newShares;
      db.prepare('UPDATE holdings SET shares = ?, avg_cost = ?, company_name = ? WHERE id = ?')
        .run(newShares, newAvg, quote.name, existing.id);
    } else {
      db.prepare(
        'INSERT INTO holdings (user_id, game_id, symbol, company_name, shares, avg_cost) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(req.user.id, game.id, symbol, quote.name, shares, quote.price);
    }

    db.prepare(
      'INSERT INTO transactions (user_id, game_id, symbol, company_name, type, shares, price, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(req.user.id, game.id, symbol, quote.name, 'buy', shares, quote.price, total);
  })();

  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({
    message: `Bought ${shares} share(s) of ${symbol} at $${quote.price.toFixed(2)}`,
    cash_balance: updated.cash_balance,
    total_cost: total,
  });
});

app.post('/api/trades/sell', requireAuth, async (req, res) => {
  let { symbol, shares } = req.body || {};
  symbol = symbol?.toUpperCase();
  shares = parseFloat(shares);

  if (!symbol || isNaN(shares) || shares <= 0) {
    return res.status(400).json({ error: 'symbol and positive shares are required' });
  }

  const game = getActiveGame();
  if (!game) return res.status(400).json({ error: 'No active game' });

  const status = gameStatus(game);
  if (status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });

  const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?')
    .get(req.user.id, game.id, symbol);

  if (!holding || holding.shares < shares - 0.000001) {
    return res.status(400).json({
      error: `Insufficient shares — you own ${holding ? holding.shares.toFixed(6) : 0} share(s) of ${symbol}`,
    });
  }

  let quote;
  try { quote = await getQuote(symbol); }
  catch (err) { return res.status(400).json({ error: err.message }); }

  const total = +(quote.price * shares).toFixed(6);

  db.transaction(() => {
    db.prepare('UPDATE portfolios SET cash_balance = cash_balance + ? WHERE user_id = ? AND game_id = ?')
      .run(total, req.user.id, game.id);

    const remaining = holding.shares - shares;
    db.prepare('UPDATE holdings SET shares = ? WHERE id = ?').run(remaining < 0.000001 ? 0 : remaining, holding.id);

    db.prepare(
      'INSERT INTO transactions (user_id, game_id, symbol, company_name, type, shares, price, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(req.user.id, game.id, symbol, quote.name, 'sell', shares, quote.price, total);
  })();

  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({
    message: `Sold ${shares} share(s) of ${symbol} at $${quote.price.toFixed(2)}`,
    cash_balance: updated.cash_balance,
    total_proceeds: total,
  });
});

app.get('/api/trades/history', requireAuth, (req, res) => {
  const game = getActiveGame();
  if (!game) return res.json([]);
  res.json(
    db.prepare(
      'SELECT * FROM transactions WHERE user_id = ? AND game_id = ? ORDER BY executed_at DESC LIMIT 200'
    ).all(req.user.id, game.id)
  );
});

// ── Catch-all → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  StockArena is running at http://0.0.0.0:${PORT}\n`);
});
