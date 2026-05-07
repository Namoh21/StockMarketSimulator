import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import db from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 8081;
const JWT_SECRET = process.env.JWT_SECRET || 'stockarena-change-this-secret-in-production';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Yahoo Finance direct API ──────────────────────────────────────────────────
const YF_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'application/json',
  'Accept-Language': 'en-US,en;q=0.9',
};

async function yfSearch(query, count = 10) {
  const url = `https://query1.finance.yahoo.com/v1/finance/search?q=${encodeURIComponent(query)}&quotesCount=${count}&newsCount=0&enableFuzzyQuery=false`;
  const res = await fetch(url, { headers: YF_HEADERS, signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`Yahoo Finance search HTTP ${res.status}`);
  const data = await res.json();
  return data?.quotes || [];
}

async function yfQuote(symbol) {
  const url = `https://query1.finance.yahoo.com/v6/finance/quote?symbols=${encodeURIComponent(symbol)}&lang=en-US&region=US`;
  const res = await fetch(url, { headers: YF_HEADERS, signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`Yahoo Finance quote HTTP ${res.status}`);
  const data = await res.json();
  const q = data?.quoteResponse?.result?.[0];
  if (!q || q.regularMarketPrice == null) throw new Error(`No price data for ${symbol}`);
  return q;
}

async function yfChart(symbol, period1) {
  const p1 = Math.floor(new Date(period1).getTime() / 1000);
  const p2 = Math.floor(Date.now() / 1000);
  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&period1=${p1}&period2=${p2}`;
  const res = await fetch(url, { headers: YF_HEADERS, signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`Yahoo Finance chart HTTP ${res.status}`);
  const data = await res.json();
  const result = data?.chart?.result?.[0];
  if (!result) return [];
  const timestamps = result.timestamp || [];
  const closes    = result.indicators?.quote?.[0]?.close || [];
  return timestamps
    .map((t, i) => ({ date: new Date(t * 1000).toISOString(), close: closes[i] }))
    .filter(d => d.close != null);
}

// ── Price cache (5-min TTL) ──────────────────────────────────────────────────
const priceCache = new Map();
const CACHE_TTL  = 5 * 60 * 1000;

async function getQuote(symbol) {
  const sym = symbol.toUpperCase();
  const cached = priceCache.get(sym);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached;
  const q = await yfQuote(sym);
  const data = {
    symbol: q.symbol || sym,
    name: q.longName || q.shortName || sym,
    price: q.regularMarketPrice,
    open: q.regularMarketOpen  || q.regularMarketPrice,
    high: q.regularMarketDayHigh || q.regularMarketPrice,
    low:  q.regularMarketDayLow  || q.regularMarketPrice,
    change:        q.regularMarketChange        || 0,
    changePercent: q.regularMarketChangePercent || 0,
    volume:   q.regularMarketVolume || 0,
    marketCap: q.marketCap || null,
    exchange:  q.exchange  || '',
    marketState: q.marketState || 'CLOSED',
    timestamp: Date.now(),
  };
  priceCache.set(sym, data);
  return data;
}

// ── Futures contract catalogue ────────────────────────────────────────────────
// multiplier = 1 (simulation units) so margin is accessible at any starting cash.
// Admin sets the margin rate (default 20%). P&L = contracts × (exit − entry) for long.
const FUTURES_CONTRACTS = [
  { symbol: 'ES=F',  name: 'S&P 500 E-mini',      category: 'Index',    description: 'Tracks the S&P 500 large-cap index' },
  { symbol: 'NQ=F',  name: 'NASDAQ 100 E-mini',    category: 'Index',    description: 'Tracks the NASDAQ 100 tech index' },
  { symbol: 'YM=F',  name: 'Dow Jones E-mini',     category: 'Index',    description: 'Tracks the 30-stock Dow Jones average' },
  { symbol: 'RTY=F', name: 'Russell 2000 E-mini',  category: 'Index',    description: 'Tracks small-cap US stocks' },
  { symbol: 'CL=F',  name: 'Crude Oil (WTI)',      category: 'Energy',   description: 'West Texas Intermediate crude oil per barrel' },
  { symbol: 'NG=F',  name: 'Natural Gas',          category: 'Energy',   description: 'Henry Hub natural gas per MMBtu' },
  { symbol: 'GC=F',  name: 'Gold',                 category: 'Metals',   description: 'COMEX gold per troy ounce' },
  { symbol: 'SI=F',  name: 'Silver',               category: 'Metals',   description: 'COMEX silver per troy ounce' },
  { symbol: 'HG=F',  name: 'Copper',               category: 'Metals',   description: 'COMEX copper per pound' },
  { symbol: 'ZB=F',  name: '30-Year T-Bond',       category: 'Rates',    description: 'US Treasury Bond futures' },
  { symbol: 'ZN=F',  name: '10-Year T-Note',       category: 'Rates',    description: 'US Treasury Note futures' },
  { symbol: '6E=F',  name: 'Euro / USD',           category: 'Currency', description: 'Euro currency vs US dollar' },
  { symbol: '6J=F',  name: 'Japanese Yen',         category: 'Currency', description: 'Japanese Yen vs US dollar' },
  { symbol: 'BTC=F', name: 'Bitcoin Futures',      category: 'Crypto',   description: 'CME Bitcoin futures contract' },
];

// ── Exchange allow-list ───────────────────────────────────────────────────────
const MARKET_EXCHANGES = {
  NYSE:   ['NYQ', 'NYS', 'NYSEArca', 'NYSEAmex'],
  NASDAQ: ['NMS', 'NGM', 'NCM', 'NAS', 'NSQ'],
  AMEX:   ['ASE', 'AMX'],
};
function isExchangeAllowed(exchange, markets) {
  if (!markets || markets.includes('ALL')) return true;
  return markets.flatMap(m => MARKET_EXCHANGES[m] || []).includes(exchange);
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ── Game middleware ───────────────────────────────────────────────────────────
function gameStatus(game) {
  if (!game) return 'none';
  const now = new Date();
  if (now < new Date(game.start_date)) return 'pending';
  if (now > new Date(game.end_date))   return 'ended';
  return 'active';
}

function loadGame(req, res, next) {
  const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(req.params.gameId);
  if (!game) return res.status(404).json({ error: 'Game not found' });
  req.game = { ...game, markets: JSON.parse(game.markets), status: gameStatus(game) };
  next();
}

function ensurePortfolio(userId, gameId, startingCash) {
  let p = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(userId, gameId);
  if (!p) {
    db.prepare('INSERT INTO portfolios (user_id, game_id, cash_balance) VALUES (?, ?, ?)').run(userId, gameId, startingCash);
    p = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(userId, gameId);
  }
  return p;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: 'Username, email, and password are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const isFirst = db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0;
    const { lastInsertRowid } = db.prepare(
      'INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)'
    ).run(username.trim(), email.trim().toLowerCase(), hash, isFirst ? 1 : 0);
    const user  = db.prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?').get(lastInsertRowid);
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username or email already taken' });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ═══════════════════════════════════════════════════════════════════════════════
// GAMES — list, create, get, update (non-destructive)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/games', requireAuth, (req, res) => {
  const games = db.prepare('SELECT * FROM game_config ORDER BY created_at DESC').all();
  const result = games.map(g => {
    const playerCount = db.prepare('SELECT COUNT(*) as c FROM portfolios WHERE game_id = ?').get(g.id).c;
    const userJoined  = !!db.prepare('SELECT id FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, g.id);
    return { ...g, markets: JSON.parse(g.markets), status: gameStatus(g), player_count: playerCount, user_joined: userJoined };
  });
  res.json(result);
});

app.post('/api/games', requireAdmin, (req, res) => {
  const { title, start_date, end_date, starting_cash, markets, allow_fractional, allow_futures, futures_margin } = req.body || {};
  if (!start_date || !end_date || !starting_cash)
    return res.status(400).json({ error: 'start_date, end_date, and starting_cash are required' });
  if (new Date(end_date) <= new Date(start_date))
    return res.status(400).json({ error: 'end_date must be after start_date' });
  if (starting_cash < 100)
    return res.status(400).json({ error: 'starting_cash must be at least $100' });

  const { lastInsertRowid } = db.prepare(
    `INSERT INTO game_config (title, start_date, end_date, starting_cash, markets, allow_fractional, allow_futures, futures_margin, is_active)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`
  ).run(
    title?.trim() || 'Stock Trading Game',
    start_date, end_date, starting_cash,
    JSON.stringify(markets?.length ? markets : ['NYSE', 'NASDAQ']),
    allow_fractional ? 1 : 0,
    allow_futures    ? 1 : 0,
    parseFloat(futures_margin) || 0.20
  );
  const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(lastInsertRowid);
  res.json({ ...game, markets: JSON.parse(game.markets), status: gameStatus(game) });
});

app.get('/api/games/:gameId', requireAuth, loadGame, (req, res) => {
  const g = req.game;
  const playerCount = db.prepare('SELECT COUNT(*) as c FROM portfolios WHERE game_id = ?').get(g.id).c;
  const userJoined  = !!db.prepare('SELECT id FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, g.id);
  res.json({ ...g, player_count: playerCount, user_joined: userJoined });
});

// Non-destructive update — cannot change starting_cash if players exist; cannot move start_date once game started
app.put('/api/games/:gameId', requireAdmin, loadGame, (req, res) => {
  const game = req.game;
  const body = req.body || {};
  const hasPlayers = db.prepare('SELECT COUNT(*) as c FROM portfolios WHERE game_id = ?').get(game.id).c > 0;

  if (body.starting_cash != null && body.starting_cash !== game.starting_cash && hasPlayers)
    return res.status(400).json({ error: 'Cannot change starting cash — players already have portfolios in this game' });
  if (body.start_date && body.start_date !== game.start_date && game.status !== 'pending')
    return res.status(400).json({ error: 'Cannot change start date — game has already started' });
  if (body.end_date && new Date(body.end_date) <= new Date(body.start_date || game.start_date))
    return res.status(400).json({ error: 'end_date must be after start_date' });

  db.prepare(
    `UPDATE game_config SET
       title            = ?,
       start_date       = ?,
       end_date         = ?,
       starting_cash    = ?,
       markets          = ?,
       allow_fractional = ?,
       allow_futures    = ?,
       futures_margin   = ?,
       is_active        = ?
     WHERE id = ?`
  ).run(
    body.title?.trim()                              ?? game.title,
    game.status === 'pending' ? (body.start_date ?? game.start_date) : game.start_date,
    body.end_date                                   ?? game.end_date,
    hasPlayers ? game.starting_cash : (body.starting_cash ?? game.starting_cash),
    JSON.stringify(body.markets?.length ? body.markets : game.markets),
    body.allow_fractional !== undefined ? (body.allow_fractional ? 1 : 0) : game.allow_fractional,
    body.allow_futures    !== undefined ? (body.allow_futures    ? 1 : 0) : game.allow_futures,
    body.futures_margin   != null       ? parseFloat(body.futures_margin) : game.futures_margin,
    body.is_active        !== undefined ? (body.is_active ? 1 : 0)        : game.is_active,
    game.id
  );
  const updated = db.prepare('SELECT * FROM game_config WHERE id = ?').get(game.id);
  res.json({ ...updated, markets: JSON.parse(updated.markets), status: gameStatus(updated) });
});

// Join a game (creates portfolio if not already joined)
app.post('/api/games/:gameId/join', requireAuth, loadGame, (req, res) => {
  const game = req.game;
  if (game.status === 'ended')
    return res.status(400).json({ error: 'This game has already ended' });
  const existing = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  if (existing) return res.json({ message: 'Already joined', already_joined: true });
  db.prepare('INSERT INTO portfolios (user_id, game_id, cash_balance) VALUES (?, ?, ?)').run(req.user.id, game.id, game.starting_cash);
  res.json({ message: `Joined "${game.title}" — starting cash $${game.starting_cash.toLocaleString()}`, already_joined: false });
});

// Leaderboard
app.get('/api/games/:gameId/leaderboard', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  const portfolios = db.prepare('SELECT p.*, u.username FROM portfolios p JOIN users u ON p.user_id = u.id WHERE p.game_id = ?').all(game.id);
  const holdings   = db.prepare('SELECT * FROM holdings WHERE game_id = ? AND shares > 0').all(game.id);
  const futures    = game.allow_futures
    ? db.prepare('SELECT * FROM futures_positions WHERE game_id = ? AND contracts > 0').all(game.id) : [];

  const byUser = {}, futuresByUser = {};
  for (const h of holdings) (byUser[h.user_id] = byUser[h.user_id] || []).push(h);
  for (const f of futures)  (futuresByUser[f.user_id] = futuresByUser[f.user_id] || []).push(f);

  const symbols = [...new Set([...holdings.map(h => h.symbol), ...futures.map(f => f.symbol)])];
  const prices = {};
  await Promise.allSettled(symbols.map(async s => {
    try { prices[s] = (await getQuote(s)).price; } catch { prices[s] = null; }
  }));

  const rows = portfolios.map(p => {
    const stockValue   = (byUser[p.user_id] || []).reduce((s, h) => s + h.shares * (prices[h.symbol] ?? h.avg_cost), 0);
    const futuresPnl   = (futuresByUser[p.user_id] || []).reduce((s, f) => {
      const pr = prices[f.symbol] ?? f.entry_price;
      return s + (f.direction === 'long' ? (pr - f.entry_price) : (f.entry_price - pr)) * f.contracts;
    }, 0);
    const totalValue = p.cash_balance + stockValue + futuresPnl;
    const gain       = totalValue - game.starting_cash;
    return { username: p.username, cash_balance: p.cash_balance, stock_value: stockValue, futures_pnl: futuresPnl, total_value: totalValue, gain, gain_pct: (gain / game.starting_cash) * 100 };
  });
  rows.sort((a, b) => b.total_value - a.total_value);
  rows.forEach((r, i) => (r.rank = i + 1));
  res.json(rows);
});

app.get('/api/games/:gameId/players', requireAdmin, loadGame, (req, res) => {
  res.json(db.prepare(
    `SELECT u.id, u.username, u.email, u.is_admin, p.cash_balance, p.joined_at
     FROM portfolios p JOIN users u ON p.user_id = u.id
     WHERE p.game_id = ? ORDER BY p.joined_at`
  ).all(req.game.id));
});

// ═══════════════════════════════════════════════════════════════════════════════
// PORTFOLIO
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/games/:gameId/portfolio', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  const portfolio = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  if (!portfolio) return res.status(404).json({ error: 'not_joined' });

  const holdings = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND shares > 0').all(req.user.id, game.id);
  const enriched = await Promise.all(holdings.map(async h => {
    try {
      const q = await getQuote(h.symbol);
      return { ...h, current_price: q.price, change: q.change, change_percent: q.changePercent,
        market_value: h.shares * q.price, gain_loss: (q.price - h.avg_cost) * h.shares,
        gain_loss_pct: ((q.price - h.avg_cost) / h.avg_cost) * 100 };
    } catch {
      return { ...h, current_price: h.avg_cost, change: 0, change_percent: 0,
        market_value: h.shares * h.avg_cost, gain_loss: 0, gain_loss_pct: 0 };
    }
  }));

  const futuresPositions = game.allow_futures
    ? db.prepare('SELECT * FROM futures_positions WHERE user_id = ? AND game_id = ? AND contracts > 0').all(req.user.id, game.id) : [];
  const enrichedFutures = await Promise.all(futuresPositions.map(async f => {
    try {
      const q = await getQuote(f.symbol);
      const unrealized = (f.direction === 'long' ? (q.price - f.entry_price) : (f.entry_price - q.price)) * f.contracts;
      return { ...f, current_price: q.price, change: q.change, unrealized_pnl: unrealized };
    } catch {
      return { ...f, current_price: f.entry_price, change: 0, unrealized_pnl: 0 };
    }
  }));

  const stockValue   = enriched.reduce((s, h) => s + h.market_value, 0);
  const futuresPnl   = enrichedFutures.reduce((s, f) => s + f.unrealized_pnl, 0);
  const totalValue   = portfolio.cash_balance + stockValue + futuresPnl;

  res.json({ game, cash_balance: portfolio.cash_balance, stock_value: stockValue,
    futures_pnl: futuresPnl, total_value: totalValue, holdings: enriched, futures_positions: enrichedFutures });
});

// ═══════════════════════════════════════════════════════════════════════════════
// STOCK ROUTES (game-agnostic)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/stocks/search', async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 1) return res.json([]);
  try {
    const quotes = await yfSearch(q, 12);
    res.json(quotes
      .filter(r => r.quoteType === 'EQUITY' && r.symbol && !r.symbol.includes('.'))
      .slice(0, 8)
      .map(r => ({ symbol: r.symbol, name: r.longname || r.shortname || r.symbol, exchange: r.exchange || '', type: r.quoteType })));
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: 'Search failed: ' + err.message });
  }
});

app.get('/api/stocks/quote/:symbol', async (req, res) => {
  try { res.json(await getQuote(req.params.symbol)); }
  catch (err) { res.status(404).json({ error: err.message }); }
});

app.get('/api/stocks/chart/:symbol', async (req, res) => {
  try {
    const period1 = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    res.json(await yfChart(req.params.symbol.toUpperCase(), period1));
  } catch { res.json([]); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// TRADES (per game)
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/games/:gameId/trades/buy', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  let { symbol, shares } = req.body || {};
  symbol = symbol?.toUpperCase(); shares = parseFloat(shares);
  if (!symbol || isNaN(shares) || shares <= 0) return res.status(400).json({ error: 'symbol and positive shares are required' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });
  if (!game.allow_fractional && !Number.isInteger(shares)) return res.status(400).json({ error: 'Fractional shares are not allowed in this game' });

  let quote;
  try { quote = await getQuote(symbol); } catch (err) { return res.status(400).json({ error: err.message }); }

  if (!isExchangeAllowed(quote.exchange, game.markets))
    return res.status(400).json({ error: `${symbol} (${quote.exchange}) is not in the allowed markets: ${game.markets.join(', ')}` });

  const total     = +(quote.price * shares).toFixed(6);
  const portfolio = ensurePortfolio(req.user.id, game.id, game.starting_cash);
  if (total > portfolio.cash_balance)
    return res.status(400).json({ error: `Insufficient funds — cost $${total.toFixed(2)}, available $${portfolio.cash_balance.toFixed(2)}` });

  db.transaction(() => {
    db.prepare('UPDATE portfolios SET cash_balance = cash_balance - ? WHERE user_id = ? AND game_id = ?').run(total, req.user.id, game.id);
    const existing = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(req.user.id, game.id, symbol);
    if (existing) {
      const ns = existing.shares + shares;
      db.prepare('UPDATE holdings SET shares = ?, avg_cost = ?, company_name = ? WHERE id = ?')
        .run(ns, (existing.avg_cost * existing.shares + quote.price * shares) / ns, quote.name, existing.id);
    } else {
      db.prepare('INSERT INTO holdings (user_id, game_id, symbol, company_name, shares, avg_cost) VALUES (?, ?, ?, ?, ?, ?)')
        .run(req.user.id, game.id, symbol, quote.name, shares, quote.price);
    }
    db.prepare('INSERT INTO transactions (user_id, game_id, symbol, company_name, type, shares, price, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(req.user.id, game.id, symbol, quote.name, 'buy', shares, quote.price, total);
  })();

  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({ message: `Bought ${shares} share(s) of ${symbol} at $${quote.price.toFixed(2)}`, cash_balance: updated.cash_balance, total_cost: total });
});

app.post('/api/games/:gameId/trades/sell', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  let { symbol, shares } = req.body || {};
  symbol = symbol?.toUpperCase(); shares = parseFloat(shares);
  if (!symbol || isNaN(shares) || shares <= 0) return res.status(400).json({ error: 'symbol and positive shares are required' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });

  const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(req.user.id, game.id, symbol);
  if (!holding || holding.shares < shares - 0.000001)
    return res.status(400).json({ error: `Insufficient shares — you own ${holding ? holding.shares.toFixed(6) : 0} share(s) of ${symbol}` });

  let quote;
  try { quote = await getQuote(symbol); } catch (err) { return res.status(400).json({ error: err.message }); }

  const total = +(quote.price * shares).toFixed(6);
  db.transaction(() => {
    db.prepare('UPDATE portfolios SET cash_balance = cash_balance + ? WHERE user_id = ? AND game_id = ?').run(total, req.user.id, game.id);
    const rem = holding.shares - shares;
    db.prepare('UPDATE holdings SET shares = ? WHERE id = ?').run(rem < 0.000001 ? 0 : rem, holding.id);
    db.prepare('INSERT INTO transactions (user_id, game_id, symbol, company_name, type, shares, price, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(req.user.id, game.id, symbol, quote.name, 'sell', shares, quote.price, total);
  })();

  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({ message: `Sold ${shares} share(s) of ${symbol} at $${quote.price.toFixed(2)}`, cash_balance: updated.cash_balance, total_proceeds: total });
});

app.get('/api/games/:gameId/trades/history', requireAuth, loadGame, (req, res) => {
  res.json(db.prepare('SELECT * FROM transactions WHERE user_id = ? AND game_id = ? ORDER BY executed_at DESC LIMIT 200').all(req.user.id, req.game.id));
});

// ═══════════════════════════════════════════════════════════════════════════════
// FUTURES (per game)
// ═══════════════════════════════════════════════════════════════════════════════

// All available futures contracts with live prices
app.get('/api/futures/contracts', requireAuth, async (req, res) => {
  const enriched = await Promise.all(FUTURES_CONTRACTS.map(async c => {
    try {
      const q = await getQuote(c.symbol);
      return { ...c, price: q.price, change: q.change, changePercent: q.changePercent, marketState: q.marketState };
    } catch {
      return { ...c, price: null, change: 0, changePercent: 0, marketState: 'CLOSED' };
    }
  }));
  res.json(enriched);
});

// User's open futures positions for a game
app.get('/api/games/:gameId/futures/positions', requireAuth, loadGame, async (req, res) => {
  if (!req.game.allow_futures) return res.json([]);
  const positions = db.prepare('SELECT * FROM futures_positions WHERE user_id = ? AND game_id = ? AND contracts > 0').all(req.user.id, req.game.id);
  const enriched  = await Promise.all(positions.map(async p => {
    try {
      const q = await getQuote(p.symbol);
      const unrealized = (p.direction === 'long' ? (q.price - p.entry_price) : (p.entry_price - q.price)) * p.contracts;
      return { ...p, current_price: q.price, change: q.change, unrealized_pnl: unrealized };
    } catch {
      return { ...p, current_price: p.entry_price, change: 0, unrealized_pnl: 0 };
    }
  }));
  res.json(enriched);
});

// Open (or add to) a futures position
app.post('/api/games/:gameId/futures/open', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_futures) return res.status(400).json({ error: 'Futures trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });

  let { symbol, direction, contracts } = req.body || {};
  symbol = symbol?.toUpperCase(); contracts = parseFloat(contracts);
  if (!symbol || !direction || !contracts || contracts <= 0) return res.status(400).json({ error: 'symbol, direction, and contracts are required' });
  if (!['long', 'short'].includes(direction)) return res.status(400).json({ error: 'direction must be "long" or "short"' });

  const contractInfo = FUTURES_CONTRACTS.find(f => f.symbol === symbol);
  if (!contractInfo) return res.status(400).json({ error: `${symbol} is not a supported futures contract` });

  let quote;
  try { quote = await getQuote(symbol); } catch (err) { return res.status(400).json({ error: err.message }); }

  const existing = db.prepare('SELECT * FROM futures_positions WHERE user_id = ? AND game_id = ? AND symbol = ? AND contracts > 0').get(req.user.id, game.id, symbol);
  if (existing && existing.direction !== direction)
    return res.status(400).json({ error: `You have an open ${existing.direction.toUpperCase()} on ${symbol}. Close it before reversing direction.` });

  const marginNeeded = +(contracts * quote.price * game.futures_margin).toFixed(6);
  const portfolio    = ensurePortfolio(req.user.id, game.id, game.starting_cash);
  if (marginNeeded > portfolio.cash_balance)
    return res.status(400).json({ error: `Insufficient margin — required $${marginNeeded.toFixed(2)}, available $${portfolio.cash_balance.toFixed(2)}` });

  db.transaction(() => {
    db.prepare('UPDATE portfolios SET cash_balance = cash_balance - ? WHERE user_id = ? AND game_id = ?').run(marginNeeded, req.user.id, game.id);
    if (existing) {
      const ns = existing.contracts + contracts;
      const na = (existing.entry_price * existing.contracts + quote.price * contracts) / ns;
      db.prepare('UPDATE futures_positions SET contracts = ?, entry_price = ?, margin_held = ? WHERE id = ?')
        .run(ns, na, existing.margin_held + marginNeeded, existing.id);
      db.prepare('INSERT INTO futures_transactions (user_id, game_id, symbol, name, direction, action, contracts, price, margin_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(req.user.id, game.id, symbol, contractInfo.name, direction, 'add', contracts, quote.price, marginNeeded);
    } else {
      db.prepare('INSERT INTO futures_positions (user_id, game_id, symbol, name, direction, contracts, entry_price, margin_held) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(req.user.id, game.id, symbol, contractInfo.name, direction, contracts, quote.price, marginNeeded);
      db.prepare('INSERT INTO futures_transactions (user_id, game_id, symbol, name, direction, action, contracts, price, margin_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(req.user.id, game.id, symbol, contractInfo.name, direction, 'open', contracts, quote.price, marginNeeded);
    }
  })();

  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({ message: `${existing ? 'Added to' : 'Opened'} ${direction.toUpperCase()} position: ${contracts} contract(s) of ${symbol} at $${quote.price.toFixed(2)}`, margin_used: marginNeeded, cash_balance: updated.cash_balance });
});

// Close (or reduce) a futures position
app.post('/api/games/:gameId/futures/close', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_futures) return res.status(400).json({ error: 'Futures trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended' });

  let { symbol, contracts } = req.body || {};
  symbol = symbol?.toUpperCase(); contracts = parseFloat(contracts);
  if (!symbol || !contracts || contracts <= 0) return res.status(400).json({ error: 'symbol and contracts are required' });

  const position = db.prepare('SELECT * FROM futures_positions WHERE user_id = ? AND game_id = ? AND symbol = ? AND contracts > 0').get(req.user.id, game.id, symbol);
  if (!position || position.contracts < contracts - 0.000001)
    return res.status(400).json({ error: `You only have ${position ? position.contracts : 0} contract(s) of ${symbol} open` });

  let quote;
  try { quote = await getQuote(symbol); } catch (err) { return res.status(400).json({ error: err.message }); }

  const pnl              = (position.direction === 'long' ? (quote.price - position.entry_price) : (position.entry_price - quote.price)) * contracts;
  const proportionMargin = (contracts / position.contracts) * position.margin_held;
  const cashReturn       = +(proportionMargin + pnl).toFixed(6);

  db.transaction(() => {
    db.prepare('UPDATE portfolios SET cash_balance = cash_balance + ? WHERE user_id = ? AND game_id = ?').run(cashReturn, req.user.id, game.id);
    const rem = position.contracts - contracts;
    if (rem < 0.000001) {
      db.prepare('UPDATE futures_positions SET contracts = 0, margin_held = 0 WHERE id = ?').run(position.id);
    } else {
      db.prepare('UPDATE futures_positions SET contracts = ?, margin_held = ? WHERE id = ?').run(rem, position.margin_held - proportionMargin, position.id);
    }
    db.prepare('INSERT INTO futures_transactions (user_id, game_id, symbol, name, direction, action, contracts, price, margin_used, realized_pnl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(req.user.id, game.id, symbol, position.name, position.direction, 'close', contracts, quote.price, proportionMargin, pnl);
  })();

  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({ message: `Closed ${contracts} contract(s) of ${symbol} — P&L: ${pnl >= 0 ? '+' : ''}$${pnl.toFixed(2)}`, realized_pnl: pnl, cash_balance: updated.cash_balance });
});

app.get('/api/games/:gameId/futures/history', requireAuth, loadGame, (req, res) => {
  res.json(db.prepare('SELECT * FROM futures_transactions WHERE user_id = ? AND game_id = ? ORDER BY executed_at DESC LIMIT 200').all(req.user.id, req.game.id));
});

// Delete a game and all associated data
app.delete('/api/games/:gameId', requireAdmin, loadGame, (req, res) => {
  const { id, title } = req.game;
  db.transaction(() => {
    db.prepare('DELETE FROM futures_transactions WHERE game_id = ?').run(id);
    db.prepare('DELETE FROM futures_positions  WHERE game_id = ?').run(id);
    db.prepare('DELETE FROM transactions       WHERE game_id = ?').run(id);
    db.prepare('DELETE FROM holdings           WHERE game_id = ?').run(id);
    db.prepare('DELETE FROM portfolios         WHERE game_id = ?').run(id);
    db.prepare('DELETE FROM game_config        WHERE id = ?').run(id);
  })();
  res.json({ message: `"${title}" and all its data have been deleted.` });
});

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/players', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at').all());
});

// ── Catch-all → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`\n  StockArena running at http://0.0.0.0:${PORT}\n`));
