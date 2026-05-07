import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import db from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 8081;

// Require a real secret; fall back to a random one (invalidates sessions on restart)
const JWT_SECRET = (() => {
  const s = process.env.JWT_SECRET;
  if (!s || s === 'stockarena-change-this-secret-in-production') {
    console.warn('\n  ⚠  JWT_SECRET not set in .env — using a random secret. All sessions reset on restart.\n     Add  JWT_SECRET=<long-random-string>  to your .env file.\n');
    return crypto.randomBytes(48).toString('hex');
  }
  return s;
})();

// ── CORS — allow AI agents running from any origin to reach the API ───────────
app.use((req, res, next) => {
  // API routes need open CORS so agents can call them from any host/script
  if (req.path.startsWith('/api/')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  next();
});

// ── Security headers (applied to non-API / HTML responses) ───────────────────
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
  }
  next();
});

// ── Simple in-memory rate limiter (auth routes) ───────────────────────────────
const _rateBuckets = new Map();
function rateLimited(key, maxHits = 10, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  let b = _rateBuckets.get(key);
  if (!b || now > b.resetAt) b = { hits: 0, resetAt: now + windowMs };
  b.hits++;
  _rateBuckets.set(key, b);
  return b.hits > maxHits;
}
// Clean stale buckets every 30 minutes
setInterval(() => { const now = Date.now(); for (const [k, b] of _rateBuckets) if (now > b.resetAt) _rateBuckets.delete(k); }, 30 * 60 * 1000);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Yahoo Finance direct API ──────────────────────────────────────────────────
const YF_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'application/json',
  'Accept-Language': 'en-US,en;q=0.9',
};

async function yfSearch(query, count = 10) {
  const hosts = ['query2.finance.yahoo.com', 'query1.finance.yahoo.com'];
  for (const host of hosts) {
    try {
      const url = `https://${host}/v1/finance/search?q=${encodeURIComponent(query)}&quotesCount=${count}&newsCount=0&enableFuzzyQuery=false`;
      const res  = await fetch(url, { headers: YF_HEADERS, signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const data = await res.json();
      return data?.quotes || [];
    } catch {}
  }
  return [];
}

async function yfQuote(symbol) {
  // v8/finance/chart is more reliable than v6/finance/quote and returns
  // the same price data in the meta field. Try query2 then query1.
  const hosts = ['query2.finance.yahoo.com', 'query1.finance.yahoo.com'];
  let lastErr;
  for (const host of hosts) {
    try {
      const url = `https://${host}/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&range=1d&includePrePost=false`;
      const res  = await fetch(url, { headers: YF_HEADERS, signal: AbortSignal.timeout(8000) });
      if (!res.ok) { lastErr = new Error(`HTTP ${res.status} from ${host}`); continue; }
      const data = await res.json();
      const meta = data?.chart?.result?.[0]?.meta;
      if (!meta || meta.regularMarketPrice == null) { lastErr = new Error(`No price data for ${symbol}`); continue; }
      const prev = meta.chartPreviousClose ?? meta.regularMarketPreviousClose ?? meta.regularMarketPrice;
      const change = meta.regularMarketPrice - prev;
      return {
        symbol:                     meta.symbol || symbol,
        longName:                   meta.longName  || meta.shortName || symbol,
        shortName:                  meta.shortName || symbol,
        regularMarketPrice:         meta.regularMarketPrice,
        regularMarketOpen:          meta.regularMarketOpen          ?? meta.regularMarketPrice,
        regularMarketDayHigh:       meta.regularMarketDayHigh       ?? meta.regularMarketPrice,
        regularMarketDayLow:        meta.regularMarketDayLow        ?? meta.regularMarketPrice,
        regularMarketVolume:        meta.regularMarketVolume        ?? 0,
        regularMarketChange:        change,
        regularMarketChangePercent: prev ? (change / prev) * 100 : 0,
        marketCap:                  null,
        exchange:                   meta.exchangeName || meta.fullExchangeName || '',
        marketState:                meta.marketState  || 'CLOSED',
      };
    } catch (err) { lastErr = err; }
  }
  throw lastErr ?? new Error(`Could not fetch quote for ${symbol}`);
}

async function yfChart(symbol, period1) {
  const p1    = Math.floor(new Date(period1).getTime() / 1000);
  const p2    = Math.floor(Date.now() / 1000);
  const hosts = ['query2.finance.yahoo.com', 'query1.finance.yahoo.com'];
  for (const host of hosts) {
    try {
      const url  = `https://${host}/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&period1=${p1}&period2=${p2}`;
      const res  = await fetch(url, { headers: YF_HEADERS, signal: AbortSignal.timeout(10000) });
      if (!res.ok) continue;
      const data   = await res.json();
      const result = data?.chart?.result?.[0];
      if (!result) return [];
      const timestamps = result.timestamp || [];
      const closes     = result.indicators?.quote?.[0]?.close || [];
      return timestamps
        .map((t, i) => ({ date: new Date(t * 1000).toISOString(), close: closes[i] }))
        .filter(d => d.close != null);
    } catch {}
  }
  return [];
}

// ── Price cache (5-min TTL) ──────────────────────────────────────────────────
const priceCache = new Map();
const CACHE_TTL  = 60 * 1000; // 60-second price cache — fresh enough for active trading

async function getQuote(symbol) {
  const sym = symbol.toUpperCase();
  if (!validSymbol(sym)) throw new Error(`Invalid symbol: ${sym}`);
  const cached = priceCache.get(sym);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached;
  const q = await yfQuote(sym);
  if (!q.regularMarketPrice || q.regularMarketPrice <= 0)
    throw new Error(`No valid price returned for ${sym}`);
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

// ── US Market hours (America/New_York) ───────────────────────────────────────
function getEasternParts() {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York',
    weekday: 'short', hour: 'numeric', minute: 'numeric', hour12: false,
  }).formatToParts(new Date());
  return {
    weekday: parts.find(p => p.type === 'weekday')?.value,
    hour:    parseInt(parts.find(p => p.type === 'hour')?.value   ?? '0'),
    minute:  parseInt(parts.find(p => p.type === 'minute')?.value ?? '0'),
  };
}

function isMarketOpen() {
  const { weekday, hour, minute } = getEasternParts();
  if (weekday === 'Sat' || weekday === 'Sun') return false;
  const t = hour * 60 + minute;
  return t >= 570 && t < 960; // 9:30 AM – 4:00 PM ET
}

function marketStatus() {
  const { weekday, hour, minute } = getEasternParts();
  const isWeekend = weekday === 'Sat' || weekday === 'Sun';
  const t   = hour * 60 + minute;
  const open = !isWeekend && t >= 570 && t < 960;
  let detail;
  if (open)          detail = 'Closes 4:00 PM ET today';
  else if (isWeekend) detail = 'Opens Monday 9:30 AM ET';
  else if (t < 570) { const m = 570 - t; detail = `Opens in ${Math.floor(m/60)}h ${m%60}m (9:30 AM ET)`; }
  else               detail = 'Opens tomorrow 9:30 AM ET';
  return { open, detail };
}

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
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;

  if (token.startsWith('ska_')) {
    // API key auth — used by AI agents
    const keyRecord = db.prepare('SELECT * FROM api_keys WHERE key_value = ?').get(token);
    if (!keyRecord) return res.status(401).json({ error: 'Invalid API key' });
    const dbUser = db.prepare('SELECT id, username, is_admin, is_approved FROM users WHERE id = ?').get(keyRecord.user_id);
    if (!dbUser) return res.status(401).json({ error: 'User not found' });
    if (!dbUser.is_approved) return res.status(403).json({ error: 'Account not approved' });
    db.prepare("UPDATE api_keys SET last_used = datetime('now') WHERE id = ?").run(keyRecord.id);
    req.user = dbUser;
    req.apiKeyLabel = keyRecord.label;
    return next();
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    // Re-check admin status from DB — JWT claim alone is not enough
    const dbUser = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
    if (!dbUser?.is_admin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ── Input validation helpers ──────────────────────────────────────────────────
const SYMBOL_RE = /^[A-Z0-9.=^-]{1,20}$/;
function validSymbol(s)  { return typeof s === 'string' && SYMBOL_RE.test(s); }
function validShares(n)  { return Number.isFinite(n) && n > 0 && n <= 1_000_000; }
const ALLOWED_MARKETS    = new Set(['NYSE', 'NASDAQ', 'AMEX', 'ALL']);

// ── Game middleware ───────────────────────────────────────────────────────────
function gameStatus(game) {
  if (!game) return 'none';
  const now = new Date();
  if (now < new Date(game.start_date)) return 'pending';
  if (now > new Date(game.end_date))   return 'ended';
  return 'active';
}

function loadGame(req, res, next) {
  try {
    const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(req.params.gameId);
    if (!game) return res.status(404).json({ error: 'Game not found' });
    let markets;
    try { markets = JSON.parse(game.markets); } catch { markets = ['NYSE', 'NASDAQ']; }
    // keep join_password on req.game for internal use; publicGame() strips it before sending to clients
    req.game = { ...game, markets, status: gameStatus(game) };
    next();
  } catch (err) {
    console.error('loadGame error:', err.message);
    res.status(500).json({ error: 'Failed to load game: ' + err.message });
  }
}

function ensurePortfolio(userId, gameId, startingCash) {
  let p = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(userId, gameId);
  if (!p) {
    db.prepare('INSERT INTO portfolios (user_id, game_id, cash_balance) VALUES (?, ?, ?)').run(userId, gameId, startingCash);
    p = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(userId, gameId);
  }
  return p;
}

// Sum of cash held by pending buy orders — these funds are reserved and unavailable.
function pendingReserved(userId, gameId) {
  return db.prepare(
    "SELECT COALESCE(SUM(reserved_amount),0) as total FROM pending_orders WHERE user_id=? AND game_id=? AND type='buy' AND status='pending'"
  ).get(userId, gameId)?.total ?? 0;
}

// Cash the user can actually spend: balance minus anything locked in pending buys.
function availableCash(userId, gameId, portfolio = null) {
  const p = portfolio ?? db.prepare('SELECT cash_balance FROM portfolios WHERE user_id=? AND game_id=?').get(userId, gameId);
  return Math.max(0, (p?.cash_balance ?? 0) - pendingReserved(userId, gameId));
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  if (rateLimited(req.ip, 5, 15 * 60 * 1000))
    return res.status(429).json({ error: 'Too many registration attempts — try again in 15 minutes' });
  const { username, password } = req.body || {};
  const email = req.body?.email?.trim() || `${username?.trim()}@local`;
  if (!username?.trim() || !password)
    return res.status(400).json({ error: 'Username and password are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const isFirst = db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0;
    const { lastInsertRowid } = db.prepare(
      'INSERT INTO users (username, email, password_hash, is_admin, is_approved) VALUES (?, ?, ?, ?, ?)'
    ).run(username.trim(), email.trim().toLowerCase(), hash, isFirst ? 1 : 0, isFirst ? 1 : 0);
    const user  = db.prepare('SELECT id, username, email, is_admin, is_approved FROM users WHERE id = ?').get(lastInsertRowid);
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username or email already taken' });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  if (rateLimited(req.ip))
    return res.status(429).json({ error: 'Too many login attempts — try again in 15 minutes' });
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin, is_approved: user.is_approved } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, is_admin, is_approved FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ═══════════════════════════════════════════════════════════════════════════════
// API KEYS — for AI agent access
// ═══════════════════════════════════════════════════════════════════════════════

// List keys for the authenticated user (key values are masked after creation)
app.get('/api/user/api-keys', requireAuth, (req, res) => {
  const keys = db.prepare('SELECT id, label, key_value, created_at, last_used FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  // Return only the first 8 chars + '...' so users can identify keys without exposing them
  res.json(keys.map(k => ({ ...k, key_preview: k.key_value.slice(0, 12) + '…', key_value: undefined })));
});

// Generate a new API key — returns the full key ONCE; not stored in plaintext after this response
app.post('/api/user/api-keys', requireAuth, (req, res) => {
  const label = (req.body?.label || 'AI Agent').slice(0, 64).trim();
  const existing = db.prepare('SELECT COUNT(*) as c FROM api_keys WHERE user_id = ?').get(req.user.id).c;
  if (existing >= 5) return res.status(400).json({ error: 'Maximum of 5 API keys per user. Revoke one before creating another.' });
  const key = 'ska_' + crypto.randomBytes(32).toString('hex');
  const { lastInsertRowid } = db.prepare('INSERT INTO api_keys (user_id, label, key_value) VALUES (?, ?, ?)').run(req.user.id, label, key);
  res.json({ id: lastInsertRowid, label, key, message: 'Save this key — it will not be shown again.' });
});

// Revoke (delete) a key
app.delete('/api/user/api-keys/:keyId', requireAuth, (req, res) => {
  const key = db.prepare('SELECT * FROM api_keys WHERE id = ? AND user_id = ?').get(req.params.keyId, req.user.id);
  if (!key) return res.status(404).json({ error: 'API key not found' });
  db.prepare('DELETE FROM api_keys WHERE id = ?').run(key.id);
  res.json({ message: `API key "${key.label}" has been revoked.` });
});

// ═══════════════════════════════════════════════════════════════════════════════
// GAMES — list, create, get, update (non-destructive)
// ═══════════════════════════════════════════════════════════════════════════════

// Strip join_password from game objects before sending to clients
function publicGame(g, extra = {}) {
  const { join_password, ...safe } = g;
  return { ...safe, markets: Array.isArray(g.markets) ? g.markets : JSON.parse(g.markets), status: gameStatus(g), ...extra };
}

app.get('/api/games', requireAuth, (req, res) => {
  const games = db.prepare('SELECT * FROM game_config ORDER BY created_at DESC').all();
  const result = games.map(g => {
    const playerCount = db.prepare('SELECT COUNT(*) as c FROM portfolios WHERE game_id = ?').get(g.id).c;
    const userJoined  = !!db.prepare('SELECT id FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, g.id);
    return publicGame(g, { player_count: playerCount, user_joined: userJoined });
  });
  res.json(result);
});

app.post('/api/games', requireAdmin, (req, res) => {
  const { title, start_date, end_date, starting_cash, markets, allow_fractional, allow_futures, futures_margin, is_private, join_password } = req.body || {};
  if (!start_date || !end_date || !starting_cash)
    return res.status(400).json({ error: 'start_date, end_date, and starting_cash are required' });
  if (new Date(end_date) <= new Date(start_date))
    return res.status(400).json({ error: 'end_date must be after start_date' });
  if (starting_cash < 100)
    return res.status(400).json({ error: 'starting_cash must be at least $100' });
  const safeMarkets = (markets?.length ? markets : ['NYSE', 'NASDAQ']).filter(m => ALLOWED_MARKETS.has(m));
  if (!safeMarkets.length)
    return res.status(400).json({ error: 'At least one valid market is required (NYSE, NASDAQ, AMEX, ALL)' });
  const priv = is_private ? 1 : 0;
  if (priv && !join_password?.trim())
    return res.status(400).json({ error: 'A join password is required for private games' });

  const { lastInsertRowid } = db.prepare(
    `INSERT INTO game_config (title, start_date, end_date, starting_cash, markets, allow_fractional, allow_futures, futures_margin, is_active, is_private, join_password)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
  ).run(
    title?.trim() || 'Stock Trading Game',
    start_date, end_date, starting_cash,
    JSON.stringify(safeMarkets),
    allow_fractional ? 1 : 0,
    allow_futures    ? 1 : 0,
    parseFloat(futures_margin) || 0.20,
    priv,
    priv ? join_password.trim() : null
  );
  const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(lastInsertRowid);
  res.json({ ...game, markets: JSON.parse(game.markets), status: gameStatus(game) });
});

app.get('/api/games/:gameId', requireAuth, loadGame, (req, res) => {
  const g = db.prepare('SELECT * FROM game_config WHERE id = ?').get(req.game.id); // re-fetch to get join_password for admin
  const playerCount = db.prepare('SELECT COUNT(*) as c FROM portfolios WHERE game_id = ?').get(g.id).c;
  const userJoined  = !!db.prepare('SELECT id FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, g.id);
  const dbUser = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
  // Admins see the join_password so they can share it; regular users never see it
  if (dbUser?.is_admin) {
    return res.json({ ...g, markets: JSON.parse(g.markets), status: gameStatus(g), player_count: playerCount, user_joined: userJoined });
  }
  res.json(publicGame(g, { player_count: playerCount, user_joined: userJoined }));
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

  const newPrivate = body.is_private !== undefined ? (body.is_private ? 1 : 0) : game.is_private;
  const newPassword = newPrivate
    ? (body.join_password?.trim() || game.join_password || null)
    : null;
  if (newPrivate && !newPassword)
    return res.status(400).json({ error: 'A join password is required for private games' });

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
       is_active        = ?,
       is_private       = ?,
       join_password    = ?
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
    newPrivate,
    newPassword,
    game.id
  );
  const updated = db.prepare('SELECT * FROM game_config WHERE id = ?').get(game.id);
  res.json({ ...updated, markets: JSON.parse(updated.markets), status: gameStatus(updated) });
});

// Join a game (creates portfolio if not already joined)
app.post('/api/games/:gameId/join', requireAuth, loadGame, (req, res) => {
  const game = req.game;
  const dbUser = db.prepare('SELECT is_approved, is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!dbUser?.is_approved)
    return res.status(403).json({ error: 'Your account is pending admin approval. You cannot join games yet.' });
  if (game.status === 'ended')
    return res.status(400).json({ error: 'This game has already ended' });
  const existing = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  if (existing) return res.json({ message: 'Already joined', already_joined: true });

  // Private game — check join password (admins bypass)
  const fullGame = db.prepare('SELECT * FROM game_config WHERE id = ?').get(game.id);
  if (fullGame.is_private && !dbUser.is_admin) {
    const supplied = req.body?.join_password?.trim();
    if (!supplied) return res.status(403).json({ error: 'private_game', message: 'This game is password-protected. Enter the join password.' });
    if (supplied !== fullGame.join_password)
      return res.status(403).json({ error: 'wrong_password', message: 'Incorrect join password.' });
  }

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
  try {
    // joined_at may be missing on very old databases — fall back gracefully
    let rows;
    try {
      rows = db.prepare(
        `SELECT u.id, u.username, u.email, u.is_admin, p.cash_balance, p.joined_at
         FROM portfolios p JOIN users u ON p.user_id = u.id
         WHERE p.game_id = ? ORDER BY p.joined_at`
      ).all(req.game.id);
    } catch {
      rows = db.prepare(
        `SELECT u.id, u.username, u.email, u.is_admin, p.cash_balance
         FROM portfolios p JOIN users u ON p.user_id = u.id
         WHERE p.game_id = ?`
      ).all(req.game.id);
    }
    res.json(rows);
  } catch (err) {
    console.error('GET /players error:', err.message);
    res.status(500).json({ error: 'Failed to load players: ' + err.message });
  }
});

// Remove a player from one game only — their account and other games are untouched
app.delete('/api/games/:gameId/players/:userId', requireAdmin, loadGame, (req, res) => {
  const { id: gameId } = req.game;
  const userId = parseInt(req.params.userId);
  const target = db.prepare('SELECT u.username, u.is_admin FROM users u JOIN portfolios p ON u.id = p.user_id WHERE u.id = ? AND p.game_id = ?').get(userId, gameId);
  if (!target) return res.status(404).json({ error: 'Player not found in this game' });
  if (target.is_admin) return res.status(400).json({ error: 'Cannot remove an admin from a game' });

  db.transaction(() => {
    db.prepare('DELETE FROM pending_orders       WHERE user_id = ? AND game_id = ?').run(userId, gameId);
    db.prepare('DELETE FROM futures_transactions WHERE user_id = ? AND game_id = ?').run(userId, gameId);
    db.prepare('DELETE FROM futures_positions    WHERE user_id = ? AND game_id = ?').run(userId, gameId);
    db.prepare('DELETE FROM transactions         WHERE user_id = ? AND game_id = ?').run(userId, gameId);
    db.prepare('DELETE FROM holdings             WHERE user_id = ? AND game_id = ?').run(userId, gameId);
    db.prepare('DELETE FROM portfolios           WHERE user_id = ? AND game_id = ?').run(userId, gameId);
  })();

  res.json({ message: `${target.username} has been removed from this game. Their account and other games are unaffected.` });
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

  const stockValue    = enriched.reduce((s, h) => s + h.market_value, 0);
  const futuresPnl    = enrichedFutures.reduce((s, f) => s + f.unrealized_pnl, 0);
  const reservedCash  = pendingReserved(req.user.id, game.id);
  const availCash     = Math.max(0, portfolio.cash_balance - reservedCash);
  const totalValue    = portfolio.cash_balance + stockValue + futuresPnl;

  res.json({ game, cash_balance: portfolio.cash_balance, reserved_cash: reservedCash,
    available_cash: availCash, stock_value: stockValue,
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
// TRADES & ORDERS (per game)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Core fill logic (shared by immediate trades and background processor) ─────
function applyFill(userId, gameId, symbol, companyName, type, shares, price) {
  const total = +(price * shares).toFixed(6);
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
      db.prepare('UPDATE portfolios SET cash_balance = cash_balance + ? WHERE user_id = ? AND game_id = ?').run(total, userId, gameId);
      const h = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(userId, gameId, symbol);
      if (h) {
        const rem = h.shares - shares;
        db.prepare('UPDATE holdings SET shares=? WHERE id=?').run(rem < 0.000001 ? 0 : rem, h.id);
      }
    }
    db.prepare('INSERT INTO transactions (user_id,game_id,symbol,company_name,type,shares,price,total) VALUES (?,?,?,?,?,?,?,?)')
      .run(userId, gameId, symbol, companyName, type, shares, price, total);
  })();
  return total;
}

// ── Market status ──────────────────────────────────────────────────────────────
app.get('/api/market/status', (req, res) => res.json(marketStatus()));

// ── Unified order submission ───────────────────────────────────────────────────
// order_type: 'market' | 'limit'   type: 'buy' | 'sell'
app.post('/api/games/:gameId/orders', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  let { symbol, type, order_type, shares, limit_price } = req.body || {};
  symbol = symbol?.toUpperCase(); shares = parseFloat(shares); limit_price = limit_price ? parseFloat(limit_price) : null;

  if (!symbol || !type || !order_type || isNaN(shares) || shares <= 0)
    return res.status(400).json({ error: 'symbol, type, order_type, and shares are required' });
  if (!validSymbol(symbol))
    return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(shares))
    return res.status(400).json({ error: 'Shares must be a finite number between 0 and 1,000,000' });
  if (!['buy','sell'].includes(type))        return res.status(400).json({ error: 'type must be buy or sell' });
  if (!['market','limit'].includes(order_type)) return res.status(400).json({ error: 'order_type must be market or limit' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });
  if (!game.allow_fractional && !Number.isInteger(shares)) return res.status(400).json({ error: 'Fractional shares are not allowed in this game' });
  if (order_type === 'limit' && (limit_price == null || limit_price <= 0)) return res.status(400).json({ error: 'A positive limit price is required for limit orders' });

  let quote;
  try { quote = await getQuote(symbol); } catch (err) { return res.status(400).json({ error: err.message }); }

  if (!isExchangeAllowed(quote.exchange, game.markets))
    return res.status(400).json({ error: `${symbol} (${quote.exchange}) is not in the allowed markets: ${game.markets.join(', ')}` });

  // For sell orders: verify the user actually owns the shares now
  if (type === 'sell') {
    const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(req.user.id, game.id, symbol);
    if (!holding || holding.shares < shares - 0.000001)
      return res.status(400).json({ error: `Insufficient shares — you own ${holding ? holding.shares.toFixed(4) : 0} share(s) of ${symbol}` });
  }

  const open = isMarketOpen();
  const portfolio = ensurePortfolio(req.user.id, game.id, game.starting_cash);

  // Market order + market open → fill immediately using available cash
  if (order_type === 'market' && open) {
    if (type === 'buy') {
      const cost  = +(quote.price * shares).toFixed(6);
      const avail = availableCash(req.user.id, game.id, portfolio);
      if (cost > avail)
        return res.status(400).json({ error: `Insufficient funds — cost $${cost.toFixed(2)}, available $${avail.toFixed(2)}` });
    }
    applyFill(req.user.id, game.id, symbol, quote.name, type, shares, quote.price);
    const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
    return res.json({ filled: true, filled_price: quote.price, cash_balance: updated.cash_balance,
      message: `${type === 'buy' ? 'Bought' : 'Sold'} ${shares} share(s) of ${symbol} at $${quote.price.toFixed(2)}` });
  }

  // For pending buy orders: compute reservation and check available cash
  let reservation = 0;
  if (type === 'buy') {
    // Limit orders reserve limit_price × shares (max they'll ever pay)
    // Market orders (queued) reserve current price × shares as the estimate
    const refPrice = (order_type === 'limit' && limit_price > 0) ? limit_price : quote.price;
    reservation    = +(refPrice * shares).toFixed(6);
    const avail    = availableCash(req.user.id, game.id, portfolio);
    if (reservation > avail)
      return res.status(400).json({
        error: `Insufficient funds — reservation $${reservation.toFixed(2)}, available $${avail.toFixed(2)}` +
               (avail < portfolio.cash_balance ? ` ($${(portfolio.cash_balance - avail).toFixed(2)} already held in other pending orders)` : ''),
      });
  }

  // Queue the order with its reservation amount
  const { lastInsertRowid } = db.prepare(
    'INSERT INTO pending_orders (user_id,game_id,symbol,company_name,type,order_type,shares,limit_price,reserved_amount) VALUES (?,?,?,?,?,?,?,?,?)'
  ).run(req.user.id, game.id, symbol, quote.name, type, order_type, shares, limit_price, reservation);

  const msg = order_type === 'market'
    ? `Market ${type} order queued — will execute at market open (9:30 AM ET)` +
      (type === 'buy' ? ` · $${reservation.toFixed(2)} reserved` : '')
    : `Limit ${type} order placed at $${limit_price.toFixed(2)}` +
      (type === 'buy' ? ` · $${reservation.toFixed(2)} reserved` : '');

  res.json({ filled: false, pending: true, order_id: lastInsertRowid, message: msg });
});

// User's pending + recent orders for a game
app.get('/api/games/:gameId/orders', requireAuth, loadGame, (req, res) => {
  res.json(db.prepare(
    'SELECT * FROM pending_orders WHERE user_id = ? AND game_id = ? ORDER BY submitted_at DESC LIMIT 100'
  ).all(req.user.id, req.game.id));
});

// Cancel a pending order
app.delete('/api/games/:gameId/orders/:orderId', requireAuth, loadGame, (req, res) => {
  const order = db.prepare('SELECT * FROM pending_orders WHERE id = ? AND user_id = ? AND game_id = ?')
    .get(req.params.orderId, req.user.id, req.game.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (order.status !== 'pending') return res.status(400).json({ error: `Cannot cancel — order is already ${order.status}` });
  db.prepare("UPDATE pending_orders SET status='cancelled', filled_at=datetime('now') WHERE id=?").run(order.id);
  res.json({ message: `Cancelled: ${order.type} ${order.shares} share(s) of ${order.symbol}` });
});

// Legacy buy/sell routes → delegate to the unified order endpoint handler
app.post('/api/games/:gameId/trades/buy', requireAuth, loadGame, async (req, res) => {
  req.body = { ...req.body, type: 'buy', order_type: 'market' };
  // Re-use the /orders handler logic by internally redirecting
  const fakeReq = { ...req, params: req.params };
  // Just call through directly — keeps code DRY
  const game = req.game;
  let { symbol, shares } = req.body;
  symbol = symbol?.toUpperCase(); shares = parseFloat(shares);
  if (!symbol || isNaN(shares) || shares <= 0) return res.status(400).json({ error: 'symbol and positive shares are required' });
  if (game.status !== 'active') return res.status(400).json({ error: game.status === 'pending' ? 'Game has not started yet' : 'Game has ended' });
  let quote; try { quote = await getQuote(symbol); } catch (err) { return res.status(400).json({ error: err.message }); }
  if (!isExchangeAllowed(quote.exchange, game.markets)) return res.status(400).json({ error: `${symbol} not in allowed markets` });
  const portfolio   = ensurePortfolio(req.user.id, game.id, game.starting_cash);
  const cost        = +(quote.price * shares).toFixed(6);
  const avail       = availableCash(req.user.id, game.id, portfolio);
  if (cost > avail) return res.status(400).json({ error: `Insufficient funds — cost $${cost.toFixed(2)}, available $${avail.toFixed(2)}` });
  if (!isMarketOpen()) {
    const { lastInsertRowid } = db.prepare('INSERT INTO pending_orders (user_id,game_id,symbol,company_name,type,order_type,shares,reserved_amount) VALUES (?,?,?,?,?,?,?,?)')
      .run(req.user.id, game.id, symbol, quote.name, 'buy', 'market', shares, cost);
    return res.json({ filled: false, pending: true, order_id: lastInsertRowid, message: `Market closed — buy order queued · $${cost.toFixed(2)} reserved` });
  }
  applyFill(req.user.id, game.id, symbol, quote.name, 'buy', shares, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({ filled: true, message: `Bought ${shares} share(s) of ${symbol} at $${quote.price.toFixed(2)}`, cash_balance: updated.cash_balance, total_cost: cost });
});

app.post('/api/games/:gameId/trades/sell', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  let { symbol, shares } = req.body || {};
  symbol = symbol?.toUpperCase(); shares = parseFloat(shares);
  if (!symbol || isNaN(shares) || shares <= 0) return res.status(400).json({ error: 'symbol and positive shares are required' });
  if (game.status !== 'active') return res.status(400).json({ error: game.status === 'pending' ? 'Game has not started yet' : 'Game has ended' });
  const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(req.user.id, game.id, symbol);
  if (!holding || holding.shares < shares - 0.000001) return res.status(400).json({ error: `Insufficient shares — you own ${holding ? holding.shares.toFixed(4) : 0} share(s) of ${symbol}` });
  let quote; try { quote = await getQuote(symbol); } catch (err) { return res.status(400).json({ error: err.message }); }
  if (!isMarketOpen()) {
    const { lastInsertRowid } = db.prepare('INSERT INTO pending_orders (user_id,game_id,symbol,company_name,type,order_type,shares) VALUES (?,?,?,?,?,?,?)')
      .run(req.user.id, game.id, symbol, quote.name, 'sell', 'market', shares);
    return res.json({ filled: false, pending: true, order_id: lastInsertRowid, message: `Market closed — sell order queued for market open (9:30 AM ET)` });
  }
  applyFill(req.user.id, game.id, symbol, quote.name, 'sell', shares, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  res.json({ filled: true, message: `Sold ${shares} share(s) of ${symbol} at $${quote.price.toFixed(2)}`, cash_balance: updated.cash_balance });
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
  if (!validSymbol(symbol))
    return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(contracts))
    return res.status(400).json({ error: 'Contracts must be a finite number between 0 and 1,000,000' });
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
  if (!validSymbol(symbol))
    return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(contracts))
    return res.status(400).json({ error: 'Contracts must be a finite number between 0 and 1,000,000' });

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
  try {
    db.transaction(() => {
      db.prepare('DELETE FROM pending_orders      WHERE game_id = ?').run(id);
      db.prepare('DELETE FROM futures_transactions WHERE game_id = ?').run(id);
      db.prepare('DELETE FROM futures_positions   WHERE game_id = ?').run(id);
      db.prepare('DELETE FROM transactions        WHERE game_id = ?').run(id);
      db.prepare('DELETE FROM holdings            WHERE game_id = ?').run(id);
      db.prepare('DELETE FROM portfolios          WHERE game_id = ?').run(id);
      db.prepare('DELETE FROM game_config         WHERE id = ?').run(id);
    })();
    res.json({ message: `"${title}" and all its data have been deleted.` });
  } catch (err) {
    console.error('Delete game error:', err.message);
    res.status(500).json({ error: 'Failed to delete game: ' + err.message });
  }
});

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/players', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, username, email, is_admin, is_approved, created_at FROM users ORDER BY created_at').all());
});

app.post('/api/admin/users/:userId/approve', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').run(target.id);
  res.json({ message: `${target.username} has been approved.` });
});

app.post('/api/admin/users/:userId/revoke', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.is_admin) return res.status(400).json({ error: 'Cannot revoke approval from an admin account.' });
  db.prepare('UPDATE users SET is_approved = 0 WHERE id = ?').run(target.id);
  res.json({ message: `${target.username}'s approval has been revoked.` });
});

app.delete('/api/admin/users/:userId', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT id, username, is_admin, is_approved FROM users WHERE id = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.is_admin) return res.status(400).json({ error: 'Cannot delete an admin account.' });
  if (target.is_approved) return res.status(400).json({ error: 'Cannot delete an approved user. Revoke approval first, or delete via game management.' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account.' });
  db.prepare('DELETE FROM api_keys WHERE user_id = ?').run(target.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  res.json({ message: `${target.username} has been deleted.` });
});

// ── Background order processor ────────────────────────────────────────────────
async function fillOrder(order) {
  const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(order.game_id);
  if (!game || gameStatus(game) !== 'active') {
    db.prepare("UPDATE pending_orders SET status='rejected', reject_reason='Game is no longer active', filled_at=datetime('now') WHERE id=?").run(order.id);
    return;
  }
  let price;
  try { price = (await getQuote(order.symbol)).price; }
  catch (err) { return; } // price unavailable — try next cycle

  const total = +(price * order.shares).toFixed(6);

  if (order.type === 'buy') {
    const portfolio = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(order.user_id, order.game_id);
    if (!portfolio || portfolio.cash_balance < total) {
      db.prepare("UPDATE pending_orders SET status='rejected', reject_reason=?, filled_at=datetime('now'), filled_price=? WHERE id=?")
        .run(`Insufficient funds at fill time ($${total.toFixed(2)} needed, $${portfolio?.cash_balance?.toFixed(2) || '0'} available)`, price, order.id);
      return;
    }
  } else {
    const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(order.user_id, order.game_id, order.symbol);
    if (!holding || holding.shares < order.shares - 0.000001) {
      db.prepare("UPDATE pending_orders SET status='rejected', reject_reason=?, filled_at=datetime('now'), filled_price=? WHERE id=?")
        .run(`Insufficient shares at fill time (owned ${holding?.shares?.toFixed(4) || 0}, needed ${order.shares})`, price, order.id);
      return;
    }
  }

  applyFill(order.user_id, order.game_id, order.symbol, order.company_name, order.type, order.shares, price);
  db.prepare("UPDATE pending_orders SET status='filled', filled_at=datetime('now'), filled_price=?, filled_total=? WHERE id=?")
    .run(price, total, order.id);
  console.log(`[Orders] Filled ${order.type} #${order.id}: ${order.shares} ${order.symbol} @ $${price.toFixed(2)}`);
}

async function processAllPendingOrders() {
  const pending = db.prepare("SELECT * FROM pending_orders WHERE status='pending' ORDER BY submitted_at").all();
  if (!pending.length) return;
  const open = isMarketOpen();
  for (const order of pending) {
    try {
      if (order.order_type === 'market') {
        if (open) await fillOrder(order);
      } else {
        // Limit orders: check price condition (triggers at any hour for game realism)
        let price;
        try { price = (await getQuote(order.symbol)).price; } catch { continue; }
        const triggered = order.type === 'buy'  ? price <= order.limit_price
                        : order.type === 'sell' ? price >= order.limit_price : false;
        if (triggered) await fillOrder(order);
      }
    } catch (err) {
      console.error(`[Orders] Error on order ${order.id}:`, err.message);
    }
  }
}

// Run immediately at startup then every 60 s
processAllPendingOrders();
setInterval(processAllPendingOrders, 60_000);

// ── Catch-all → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Global error handler — catches any unhandled throw in route handlers ──────
app.use((err, req, res, _next) => {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
  if (!res.headersSent) res.status(500).json({ error: err.message || 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`\n  StockArena running at http://0.0.0.0:${PORT}\n`));
