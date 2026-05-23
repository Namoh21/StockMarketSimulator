import { execSync } from 'child_process';
import { existsSync as fs_existsSync } from 'fs';
import compression from 'compression';
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import db from './db.js';
import { configureMailer, isEmailEnabled, sendEmail, buildTradeEmail, buildDailySummaryEmail, buildRankingEmail, buildTestEmail } from './email.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.disable('x-powered-by'); // don't leak framework fingerprint
const PORT = process.env.PORT || 8081;

// ── JWT secret — must be set in production ────────────────────────────────────
const JWT_SECRET = (() => {
  const s = process.env.JWT_SECRET;
  if (!s || s === 'stockarena-change-this-secret-in-production') {
    console.warn('\n  ⚠  JWT_SECRET not set in .env — using a random secret. All sessions reset on restart.\n     Add  JWT_SECRET=<long-random-string>  to your .env file.\n');
    return crypto.randomBytes(48).toString('hex');
  }
  return s;
})();

// ── AES-256-GCM field encryption (protects SMTP password, join passwords in DB) ─
// Key is derived from JWT_SECRET — changing the secret invalidates all encrypted fields.
const _ENC_KEY = crypto.scryptSync(JWT_SECRET, 'stockarena-field-enc-v1', 32);

function encryptField(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(12);
  const c  = crypto.createCipheriv('aes-256-gcm', _ENC_KEY, iv);
  const enc = Buffer.concat([c.update(String(plaintext), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}

function decryptField(ciphertext) {
  if (!ciphertext) return null;
  try {
    const buf = Buffer.from(ciphertext, 'base64');
    const d   = crypto.createDecipheriv('aes-256-gcm', _ENC_KEY, buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
  } catch { return null; }
}

// SHA-256 hash for API key lookup (keys are never stored in plaintext)
function hashApiKey(key) { return crypto.createHash('sha256').update(key).digest('hex'); }

// ── Token blacklist — DB-backed so revocations survive server restarts ────────
function blacklistToken(jti, exp) {
  if (!jti) return;
  try { db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti, exp) VALUES (?, ?)').run(jti, exp); } catch {}
}
function isBlacklisted(jti) {
  if (!jti) return false;
  const row = db.prepare('SELECT exp FROM revoked_tokens WHERE jti = ?').get(jti);
  if (!row) return false;
  if (Date.now() / 1000 > row.exp) { // expired — clean it up
    try { db.prepare('DELETE FROM revoked_tokens WHERE jti = ?').run(jti); } catch {}
    return false;
  }
  return true;
}
// Purge fully-expired revoked tokens once an hour
try { db.prepare('DELETE FROM revoked_tokens WHERE exp < ?').run(Math.floor(Date.now() / 1000)); } catch {}
setInterval(() => {
  try { db.prepare('DELETE FROM revoked_tokens WHERE exp < ?').run(Math.floor(Date.now() / 1000)); } catch {}
}, 3_600_000);

// ── SMTP config helpers ────────────────────────────────────────────────────────
function getSetting(key) {
  return db.prepare('SELECT value FROM server_settings WHERE key = ?').get(key)?.value || '';
}
function setSetting(key, value) {
  db.prepare('INSERT INTO server_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value ?? '');
}

// Load SMTP at startup — DB values take priority over env vars; password is AES-encrypted in DB
(async () => {
  const host    = getSetting('smtp_host') || process.env.SMTP_HOST || '';
  const port    = getSetting('smtp_port') || process.env.SMTP_PORT || '587';
  const user    = getSetting('smtp_user') || process.env.SMTP_USER || '';
  const rawPass = getSetting('smtp_pass') || '';
  const pass    = (rawPass ? (decryptField(rawPass) ?? rawPass) : '') || process.env.SMTP_PASS || '';
  const from    = getSetting('email_from') || process.env.EMAIL_FROM || '';
  const baseUrl = getSetting('base_url')   || process.env.BASE_URL   || `http://localhost:${PORT}`;
  if (host && user && pass) await configureMailer({ host, port, user, pass, from, baseUrl });
  else if (from || baseUrl) await configureMailer({ from, baseUrl });
})();

// ── CORS — AI agents can use API keys from any origin; browsers restricted ────
// API keys use Authorization header (not cookies) so wildcard is less dangerous,
// but we still restrict to the configured origin where possible.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    const configuredOrigin = getSetting('base_url') || process.env.BASE_URL || '';
    // Use configured origin for browser clients; fall back to wildcard for agents
    const origin = configuredOrigin || '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    if (origin !== '*') res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  next();
});

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (!req.path.startsWith('/api/')) {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'");
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

app.use(compression()); // gzip all responses — biggest perf win on a Pi
app.use(express.json({ limit: '50kb' })); // prevent oversized payload DoS
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',           // browsers cache static assets
  setHeaders(res, p) {
    // Never cache index.html so users always get the latest version
    if (p.endsWith('index.html')) res.setHeader('Cache-Control', 'no-cache');
  },
}));

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
const CACHE_TTL  = 2 * 60 * 1000; // 2-min price cache — balances freshness vs Yahoo API load

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
  // Index
  { symbol: 'ES=F',  name: 'S&P 500 E-mini',      category: 'Index',        description: 'Tracks the S&P 500 large-cap index' },
  { symbol: 'NQ=F',  name: 'NASDAQ 100 E-mini',    category: 'Index',        description: 'Tracks the NASDAQ 100 tech index' },
  { symbol: 'YM=F',  name: 'Dow Jones E-mini',     category: 'Index',        description: 'Tracks the 30-stock Dow Jones average' },
  { symbol: 'RTY=F', name: 'Russell 2000 E-mini',  category: 'Index',        description: 'Tracks small-cap US stocks' },
  // Energy
  { symbol: 'CL=F',  name: 'Crude Oil (WTI)',      category: 'Energy',       description: 'West Texas Intermediate crude oil per barrel' },
  { symbol: 'BZ=F',  name: 'Crude Oil (Brent)',    category: 'Energy',       description: 'North Sea Brent crude oil per barrel' },
  { symbol: 'NG=F',  name: 'Natural Gas',          category: 'Energy',       description: 'Henry Hub natural gas per MMBtu' },
  { symbol: 'RB=F',  name: 'RBOB Gasoline',        category: 'Energy',       description: 'Reformulated gasoline blendstock per gallon' },
  { symbol: 'HO=F',  name: 'Heating Oil',          category: 'Energy',       description: 'No. 2 heating oil per gallon' },
  // Metals
  { symbol: 'GC=F',  name: 'Gold',                 category: 'Metals',       description: 'COMEX gold per troy ounce' },
  { symbol: 'SI=F',  name: 'Silver',               category: 'Metals',       description: 'COMEX silver per troy ounce' },
  { symbol: 'HG=F',  name: 'Copper',               category: 'Metals',       description: 'COMEX copper per pound' },
  { symbol: 'PL=F',  name: 'Platinum',             category: 'Metals',       description: 'NYMEX platinum per troy ounce' },
  { symbol: 'PA=F',  name: 'Palladium',            category: 'Metals',       description: 'NYMEX palladium per troy ounce' },
  // Agricultural
  { symbol: 'ZC=F',  name: 'Corn',                 category: 'Agricultural', description: 'CBOT corn per bushel' },
  { symbol: 'ZW=F',  name: 'Wheat',                category: 'Agricultural', description: 'CBOT wheat per bushel' },
  { symbol: 'ZS=F',  name: 'Soybeans',             category: 'Agricultural', description: 'CBOT soybeans per bushel' },
  { symbol: 'ZM=F',  name: 'Soybean Meal',         category: 'Agricultural', description: 'CBOT soybean meal per short ton' },
  { symbol: 'ZL=F',  name: 'Soybean Oil',          category: 'Agricultural', description: 'CBOT soybean oil per pound' },
  { symbol: 'KC=F',  name: 'Coffee',               category: 'Agricultural', description: 'ICE Coffee C per pound' },
  { symbol: 'CT=F',  name: 'Cotton',               category: 'Agricultural', description: 'ICE Cotton No. 2 per pound' },
  { symbol: 'SB=F',  name: 'Sugar',                category: 'Agricultural', description: 'ICE Sugar No. 11 per pound' },
  { symbol: 'CC=F',  name: 'Cocoa',                category: 'Agricultural', description: 'ICE Cocoa per metric ton' },
  { symbol: 'LE=F',  name: 'Live Cattle',          category: 'Agricultural', description: 'CME live cattle per pound' },
  { symbol: 'HE=F',  name: 'Lean Hogs',            category: 'Agricultural', description: 'CME lean hogs per pound' },
  // Rates
  { symbol: 'ZB=F',  name: '30-Year T-Bond',       category: 'Rates',        description: 'US Treasury Bond futures' },
  { symbol: 'ZN=F',  name: '10-Year T-Note',       category: 'Rates',        description: 'US Treasury Note futures' },
  { symbol: 'ZF=F',  name: '5-Year T-Note',        category: 'Rates',        description: 'US 5-Year Treasury Note futures' },
  { symbol: 'ZT=F',  name: '2-Year T-Note',        category: 'Rates',        description: 'US 2-Year Treasury Note futures' },
  // Currency
  { symbol: '6E=F',  name: 'Euro / USD',           category: 'Currency',     description: 'Euro currency vs US dollar' },
  { symbol: '6J=F',  name: 'Japanese Yen',         category: 'Currency',     description: 'Japanese Yen vs US dollar' },
  { symbol: '6B=F',  name: 'British Pound',        category: 'Currency',     description: 'British Pound vs US dollar' },
  { symbol: '6C=F',  name: 'Canadian Dollar',      category: 'Currency',     description: 'Canadian Dollar vs US dollar' },
  { symbol: '6A=F',  name: 'Australian Dollar',    category: 'Currency',     description: 'Australian Dollar vs US dollar' },
  { symbol: '6S=F',  name: 'Swiss Franc',          category: 'Currency',     description: 'Swiss Franc vs US dollar' },
  // Crypto
  { symbol: 'BTC=F', name: 'Bitcoin Futures',      category: 'Crypto',       description: 'CME Bitcoin futures contract' },
];

// ── Precious metals spot catalogue ───────────────────────────────────────────
// Uses nearby futures symbols as spot price proxies (COMEX/NYMEX).
// Metals trade 24/5 — no US market-hours restriction applied.
const PRECIOUS_METALS = [
  { symbol: 'GC=F', name: 'Gold',      unit: 'oz', description: 'COMEX gold per troy ounce' },
  { symbol: 'SI=F', name: 'Silver',    unit: 'oz', description: 'COMEX silver per troy ounce' },
  { symbol: 'PL=F', name: 'Platinum',  unit: 'oz', description: 'NYMEX platinum per troy ounce' },
  { symbol: 'PA=F', name: 'Palladium', unit: 'oz', description: 'NYMEX palladium per troy ounce' },
];
const METAL_SYMBOLS = new Set(PRECIOUS_METALS.map(m => m.symbol));

// ── Forex spot pairs ──────────────────────────────────────────────────────────
const FOREX_PAIRS = [
  { symbol: 'EURUSD=X', name: 'EUR/USD', category: 'Majors',   description: 'Euro vs US Dollar' },
  { symbol: 'GBPUSD=X', name: 'GBP/USD', category: 'Majors',   description: 'British Pound vs US Dollar' },
  { symbol: 'USDJPY=X', name: 'USD/JPY', category: 'Majors',   description: 'US Dollar vs Japanese Yen' },
  { symbol: 'USDCHF=X', name: 'USD/CHF', category: 'Majors',   description: 'US Dollar vs Swiss Franc' },
  { symbol: 'USDCAD=X', name: 'USD/CAD', category: 'Majors',   description: 'US Dollar vs Canadian Dollar' },
  { symbol: 'AUDUSD=X', name: 'AUD/USD', category: 'Majors',   description: 'Australian Dollar vs US Dollar' },
  { symbol: 'NZDUSD=X', name: 'NZD/USD', category: 'Majors',   description: 'New Zealand Dollar vs US Dollar' },
  { symbol: 'EURGBP=X', name: 'EUR/GBP', category: 'Crosses',  description: 'Euro vs British Pound' },
  { symbol: 'EURJPY=X', name: 'EUR/JPY', category: 'Crosses',  description: 'Euro vs Japanese Yen' },
  { symbol: 'GBPJPY=X', name: 'GBP/JPY', category: 'Crosses',  description: 'British Pound vs Japanese Yen' },
  { symbol: 'USDMXN=X', name: 'USD/MXN', category: 'Emerging', description: 'US Dollar vs Mexican Peso' },
  { symbol: 'USDINR=X', name: 'USD/INR', category: 'Emerging', description: 'US Dollar vs Indian Rupee' },
  { symbol: 'USDCNY=X', name: 'USD/CNY', category: 'Emerging', description: 'US Dollar vs Chinese Yuan' },
  { symbol: 'USDBRL=X', name: 'USD/BRL', category: 'Emerging', description: 'US Dollar vs Brazilian Real' },
];
const FOREX_SYMBOLS = new Set(FOREX_PAIRS.map(f => f.symbol));

// ── Crypto spot assets ────────────────────────────────────────────────────────
const CRYPTO_ASSETS = [
  { symbol: 'BTC-USD',  name: 'Bitcoin',   description: 'The original proof-of-work cryptocurrency' },
  { symbol: 'ETH-USD',  name: 'Ethereum',  description: 'Smart contract and DeFi platform' },
  { symbol: 'SOL-USD',  name: 'Solana',    description: 'High-throughput proof-of-stake blockchain' },
  { symbol: 'BNB-USD',  name: 'BNB',       description: 'Binance exchange native token' },
  { symbol: 'XRP-USD',  name: 'XRP',       description: 'Cross-border payment settlement network' },
  { symbol: 'ADA-USD',  name: 'Cardano',   description: 'Peer-reviewed proof-of-stake blockchain' },
  { symbol: 'DOGE-USD', name: 'Dogecoin',  description: 'Original meme-based cryptocurrency' },
  { symbol: 'AVAX-USD', name: 'Avalanche', description: 'Fast finality smart contract platform' },
  { symbol: 'LTC-USD',  name: 'Litecoin',  description: 'Early peer-to-peer digital currency' },
  { symbol: 'DOT-USD',  name: 'Polkadot',  description: 'Multi-chain interoperability protocol' },
  { symbol: 'LINK-USD', name: 'Chainlink', description: 'Decentralized oracle data network' },
];
const CRYPTO_SYMBOLS = new Set(CRYPTO_ASSETS.map(c => c.symbol));

// Combined set of all non-stock spot symbols (used for portfolio filtering)
const ALL_SPOT_SYMBOLS = new Set([...METAL_SYMBOLS, ...FOREX_SYMBOLS, ...CRYPTO_SYMBOLS]);

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
    // API key auth — look up by SHA-256 hash only (plaintext never stored)
    const keyHash = hashApiKey(token);
    const keyRecord = db.prepare('SELECT * FROM api_keys WHERE key_hash = ?').get(keyHash);
    if (!keyRecord) return res.status(401).json({ error: 'Invalid API key' });
    const dbUser = db.prepare('SELECT id, username, is_admin, is_approved FROM users WHERE id = ?').get(keyRecord.user_id);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });
    if (!dbUser.is_approved) return res.status(403).json({ error: 'Account not approved' });
    db.prepare("UPDATE api_keys SET last_used = datetime('now') WHERE id = ?").run(keyRecord.id);
    req.user = dbUser;
    req.apiKeyLabel = keyRecord.label;
    return next();
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (isBlacklisted(payload.jti)) return res.status(401).json({ error: 'Session expired — please log in again' });
    req.user = payload;
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

// ── JWT signing helper ────────────────────────────────────────────────────────
function signToken(user) {
  const jti = crypto.randomBytes(16).toString('hex');
  return jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin, jti }, JWT_SECRET, { expiresIn: '24h' });
}

// ── Audit logger ──────────────────────────────────────────────────────────────
function audit(req, action, detail = '') {
  const who = req.user?.username || req.ip;
  console.log(`[AUDIT] ${new Date().toISOString()} ${who} — ${action}${detail ? ': ' + detail : ''}`);
}

// ── Input validation helpers ──────────────────────────────────────────────────
const SYMBOL_RE = /^[A-Z0-9.=^-]{1,20}$/;
function validSymbol(s)  { return typeof s === 'string' && SYMBOL_RE.test(s); }
function validShares(n)  { return Number.isFinite(n) && n > 0 && n <= 1_000_000; }
function validTotal(n)   { return Number.isFinite(n) && n >= 0; } // guards against NaN/Infinity in price×shares
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
    res.status(500).json({ error: 'Failed to load game' });
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
  if (rateLimited(req.ip, 5, 15 * 60 * 1000)) {
    audit(req, 'RATE_LIMIT_EXCEEDED', 'register');
    return res.status(429).json({ error: 'Too many registration attempts — try again in 15 minutes' });
  }
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
    const token = signToken(user);
    audit(req, 'REGISTER', user.username);
    res.json({ token, user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username or email already taken' });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  if (rateLimited(req.ip)) {
    audit(req, 'RATE_LIMIT_EXCEEDED', 'login');
    return res.status(429).json({ error: 'Too many login attempts — try again in 15 minutes' });
  }
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken(user);
  audit(req, 'LOGIN', user.username);
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin, is_approved: user.is_approved } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, is_admin, is_approved FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  if (req.user.jti) blacklistToken(req.user.jti, req.user.exp);
  audit(req, 'LOGOUT');
  res.json({ message: 'Logged out.' });
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
  const label = (req.body?.label || 'AI Agent').trim().slice(0, 64);
  if (!label) return res.status(400).json({ error: 'Label cannot be empty' });
  const existing = db.prepare('SELECT COUNT(*) as c FROM api_keys WHERE user_id = ?').get(req.user.id).c;
  if (existing >= 5) return res.status(400).json({ error: 'Maximum of 5 API keys per user. Revoke one before creating another.' });
  const key      = 'ska_' + crypto.randomBytes(32).toString('hex');
  const keyHash  = hashApiKey(key);
  const keyPreview = key.slice(0, 12) + '…';
  // Store SHA-256 hash only — the plaintext key is shown once and never persisted
  const { lastInsertRowid } = db.prepare(
    'INSERT INTO api_keys (user_id, label, key_value, key_hash, key_preview) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.id, label, keyHash, keyHash, keyPreview);
  audit(req, 'API_KEY_CREATED', label);
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
// USER PROFILE & NOTIFICATION PREFERENCES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/user/profile', requireAuth, (req, res) => {
  const u = db.prepare('SELECT id, username, email, notify_trades, notify_daily, notify_ranking FROM users WHERE id = ?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ ...u, email_set: u.email && !u.email.endsWith('@local') });
});

app.put('/api/user/profile', requireAuth, (req, res) => {
  const { email, notify_trades, notify_daily, notify_ranking } = req.body || {};
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (email !== undefined) {
    if (email && email.length > 255)
      return res.status(400).json({ error: 'Email address too long (max 255 characters)' });
    if (email && !emailRe.test(email))
      return res.status(400).json({ error: 'Invalid email address' });
    // Check uniqueness (only if setting a real email, skip @local placeholders)
    if (email) {
      const conflict = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE AND id != ?').get(email.trim(), req.user.id);
      if (conflict) return res.status(400).json({ error: 'That email is already in use by another account' });
    }
  }

  const current = db.prepare('SELECT email, notify_trades, notify_daily, notify_ranking FROM users WHERE id = ?').get(req.user.id);
  const newEmail = email !== undefined ? (email?.trim() || `${req.user.username}@local`) : current.email;

  db.prepare('UPDATE users SET email = ?, notify_trades = ?, notify_daily = ?, notify_ranking = ? WHERE id = ?').run(
    newEmail,
    notify_trades  !== undefined ? (notify_trades  ? 1 : 0) : current.notify_trades,
    notify_daily   !== undefined ? (notify_daily   ? 1 : 0) : current.notify_daily,
    notify_ranking !== undefined ? (notify_ranking ? 1 : 0) : current.notify_ranking,
    req.user.id
  );
  res.json({ message: 'Preferences saved.' });
});

app.post('/api/user/profile/test-email', requireAuth, async (req, res) => {
  const u = db.prepare('SELECT username, email FROM users WHERE id = ?').get(req.user.id);
  if (!u?.email || u.email.endsWith('@local'))
    return res.status(400).json({ error: 'Set a real email address first.' });
  if (!isEmailEnabled())
    return res.status(503).json({ error: 'Email is not configured on this server. Ask your admin to set SMTP env vars.' });
  const ok = await sendEmail(u.email, 'Test Email — StockArena', buildTestEmail(u.username));
  ok ? res.json({ message: `Test email sent to ${u.email}` })
     : res.status(500).json({ error: 'Failed to send — check server SMTP configuration.' });
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
  const { title, start_date, end_date, starting_cash, markets, allow_fractional, allow_futures, futures_margin, allow_metals, allow_forex, allow_crypto, is_private, join_password } = req.body || {};
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
    `INSERT INTO game_config (title, start_date, end_date, starting_cash, markets, allow_fractional, allow_futures, futures_margin, allow_metals, allow_forex, allow_crypto, is_active, is_private, join_password)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
  ).run(
    title?.trim() || 'Stock Trading Game',
    start_date, end_date, starting_cash,
    JSON.stringify(safeMarkets),
    allow_fractional ? 1 : 0,
    allow_futures    ? 1 : 0,
    parseFloat(futures_margin) || 0.20,
    allow_metals     ? 1 : 0,
    allow_forex      ? 1 : 0,
    allow_crypto     ? 1 : 0,
    priv,
    priv ? encryptField(join_password.trim()) : null  // stored encrypted
  );
  audit(req, 'CREATE_GAME', title?.trim() || 'Stock Trading Game');
  const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(lastInsertRowid);
  res.json({ ...game, markets: JSON.parse(game.markets), status: gameStatus(game) });
});

app.get('/api/games/:gameId', requireAuth, loadGame, (req, res) => {
  const g = db.prepare('SELECT * FROM game_config WHERE id = ?').get(req.game.id);
  const playerCount = db.prepare('SELECT COUNT(*) as c FROM portfolios WHERE game_id = ?').get(g.id).c;
  const userJoined  = !!db.prepare('SELECT id FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, g.id);
  const dbUser = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
  // Non-admins cannot see private games they haven't joined (prevents enumeration)
  if (g.is_private && !userJoined && !dbUser?.is_admin)
    return res.status(404).json({ error: 'Game not found' });
  // Admins see the decrypted join_password so they can share it; regular users never see it
  if (dbUser?.is_admin) {
    const decrypted = g.join_password ? (decryptField(g.join_password) ?? g.join_password) : null;
    return res.json({ ...g, join_password: decrypted, markets: JSON.parse(g.markets), status: gameStatus(g), player_count: playerCount, user_joined: userJoined });
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
  // Preserve existing encrypted password if admin didn't supply a new one
  const existingPw = game.join_password; // already encrypted in DB
  const newPassword = newPrivate
    ? (body.join_password?.trim() ? encryptField(body.join_password.trim()) : existingPw)
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
       allow_metals     = ?,
       allow_forex      = ?,
       allow_crypto     = ?,
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
    body.allow_metals     !== undefined ? (body.allow_metals     ? 1 : 0) : game.allow_metals,
    body.allow_forex      !== undefined ? (body.allow_forex      ? 1 : 0) : game.allow_forex,
    body.allow_crypto     !== undefined ? (body.allow_crypto     ? 1 : 0) : game.allow_crypto,
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

  // Private game — rate-limit password attempts then compare (admins bypass)
  const fullGame = db.prepare('SELECT * FROM game_config WHERE id = ?').get(game.id);
  if (fullGame.is_private && !dbUser.is_admin) {
    if (rateLimited(`join:${req.user.id}:${game.id}`, 5, 10 * 60 * 1000)) {
      audit(req, 'RATE_LIMIT_EXCEEDED', `join game ${game.id}`);
      return res.status(429).json({ error: 'Too many join attempts — try again in 10 minutes.' });
    }
    const supplied = req.body?.join_password?.trim();
    if (!supplied) return res.status(403).json({ error: 'private_game', message: 'This game is password-protected. Enter the join password.' });
    const storedPw = decryptField(fullGame.join_password) ?? fullGame.join_password;
    // Use timing-safe comparison to prevent timing attacks
    const sBuf = Buffer.from(supplied.padEnd(storedPw.length, '\0'));
    const dBuf = Buffer.from(storedPw.padEnd(supplied.length, '\0'));
    const same = sBuf.length === dBuf.length && crypto.timingSafeEqual(sBuf, dBuf);
    if (!same)
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
    res.status(500).json({ error: 'Failed to load players' });
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
  if (!portfolio) return res.status(404).json({ error: 'not_joined' }); // client checks this exact string to redirect

  const holdings        = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND shares > 0').all(req.user.id, game.id);
  const futuresPositions = game.allow_futures
    ? db.prepare('SELECT * FROM futures_positions WHERE user_id = ? AND game_id = ? AND contracts > 0').all(req.user.id, game.id) : [];

  // Fetch all prices in one parallel batch (holdings + futures together)
  const allSymbols = [...new Set([...holdings.map(h => h.symbol), ...futuresPositions.map(f => f.symbol)])];
  const prices = {};
  await Promise.allSettled(allSymbols.map(async sym => {
    try { prices[sym] = await getQuote(sym); } catch {}
  }));

  const enriched = holdings.map(h => {
    const q = prices[h.symbol];
    if (!q) return { ...h, current_price: h.avg_cost, change: 0, change_percent: 0, market_value: h.shares * h.avg_cost, gain_loss: 0, gain_loss_pct: 0 };
    return { ...h, current_price: q.price, change: q.change, change_percent: q.changePercent,
      market_value: h.shares * q.price, gain_loss: (q.price - h.avg_cost) * h.shares,
      gain_loss_pct: ((q.price - h.avg_cost) / h.avg_cost) * 100 };
  });

  const enrichedFutures = futuresPositions.map(f => {
    const q = prices[f.symbol];
    if (!q) return { ...f, current_price: f.entry_price, change: 0, unrealized_pnl: 0 };
    const unrealized = (f.direction === 'long' ? (q.price - f.entry_price) : (f.entry_price - q.price)) * f.contracts;
    return { ...f, current_price: q.price, change: q.change, unrealized_pnl: unrealized };
  });

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

app.get('/api/stocks/search', requireAuth, async (req, res) => {
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
    res.status(500).json({ error: 'Search unavailable' });
  }
});

app.get('/api/stocks/quote/:symbol', requireAuth, async (req, res) => {
  try { res.json(await getQuote(req.params.symbol)); }
  catch { res.status(404).json({ error: 'Quote unavailable' }); }
});

app.get('/api/stocks/chart/:symbol', requireAuth, async (req, res) => {
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
app.get('/api/market/status', requireAuth, (req, res) => res.json(marketStatus()));

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
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch quote — symbol may be invalid or market data unavailable' }); }

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
    const fillTotal = applyFill(req.user.id, game.id, symbol, quote.name, type, shares, quote.price);
    const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
    fireTradeNotification(req.user.id, game.id, symbol, quote.name, type, shares, quote.price, fillTotal);
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
  let quote; try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch quote — symbol may be invalid or market data unavailable' }); }
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
  let quote; try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch quote — symbol may be invalid or market data unavailable' }); }
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
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch quote — symbol may be invalid or market data unavailable' }); }

  const existing = db.prepare('SELECT * FROM futures_positions WHERE user_id = ? AND game_id = ? AND symbol = ? AND contracts > 0').get(req.user.id, game.id, symbol);
  if (existing && existing.direction !== direction)
    return res.status(400).json({ error: `You have an open ${existing.direction.toUpperCase()} on ${symbol}. Close it before reversing direction.` });

  const marginNeeded = +(contracts * quote.price * game.futures_margin).toFixed(6);
  if (!validTotal(marginNeeded)) return res.status(400).json({ error: 'Invalid margin calculation — check contracts and price' });
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
  if (!['long', 'short'].includes(position.direction))
    return res.status(500).json({ error: 'Position has invalid direction — contact admin' });

  let quote;
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch quote — symbol may be invalid or market data unavailable' }); }

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

// ═══════════════════════════════════════════════════════════════════════════════
// PRECIOUS METALS (per game)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/metals/list', requireAuth, async (req, res) => {
  const enriched = await Promise.all(PRECIOUS_METALS.map(async m => {
    try {
      const q = await getQuote(m.symbol);
      return { ...m, price: q.price, change: q.change, changePercent: q.changePercent, marketState: q.marketState };
    } catch {
      return { ...m, price: null, change: 0, changePercent: 0, marketState: 'CLOSED' };
    }
  }));
  res.json(enriched);
});

app.post('/api/games/:gameId/metals/buy', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_metals) return res.status(400).json({ error: 'Precious metals trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });

  let { symbol, oz } = req.body || {};
  symbol = symbol?.toUpperCase(); oz = parseFloat(oz);
  if (!symbol || isNaN(oz) || oz <= 0) return res.status(400).json({ error: 'symbol and positive oz are required' });
  if (!validSymbol(symbol)) return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(oz))     return res.status(400).json({ error: 'Quantity must be between 0 and 1,000,000' });

  const metal = PRECIOUS_METALS.find(m => m.symbol === symbol);
  if (!metal) return res.status(400).json({ error: `${symbol} is not a supported precious metal` });

  let quote;
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch price — market data unavailable' }); }

  const portfolio = ensurePortfolio(req.user.id, game.id, game.starting_cash);
  const cost = +(quote.price * oz).toFixed(6);
  if (!validTotal(cost)) return res.status(400).json({ error: 'Invalid cost calculation' });
  const avail = availableCash(req.user.id, game.id, portfolio);
  if (cost > avail) return res.status(400).json({ error: `Insufficient funds — cost $${cost.toFixed(2)}, available $${avail.toFixed(2)}` });

  applyFill(req.user.id, game.id, symbol, metal.name, 'buy', oz, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  audit(req, 'METALS_BUY', `${oz} oz ${metal.name} @ $${quote.price.toFixed(2)}`);
  res.json({ filled: true, message: `Bought ${oz} oz of ${metal.name} at $${quote.price.toFixed(2)}/oz`, cash_balance: updated.cash_balance, total_cost: cost });
});

app.post('/api/games/:gameId/metals/sell', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_metals) return res.status(400).json({ error: 'Precious metals trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended' });

  let { symbol, oz } = req.body || {};
  symbol = symbol?.toUpperCase(); oz = parseFloat(oz);
  if (!symbol || isNaN(oz) || oz <= 0) return res.status(400).json({ error: 'symbol and positive oz are required' });
  if (!validSymbol(symbol)) return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(oz))     return res.status(400).json({ error: 'Quantity must be between 0 and 1,000,000' });

  const metal = PRECIOUS_METALS.find(m => m.symbol === symbol);
  if (!metal) return res.status(400).json({ error: `${symbol} is not a supported precious metal` });

  const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(req.user.id, game.id, symbol);
  if (!holding || holding.shares < oz - 0.000001)
    return res.status(400).json({ error: `Insufficient — you own ${holding ? holding.shares.toFixed(6) : 0} oz of ${metal.name}` });

  let quote;
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch price — market data unavailable' }); }

  applyFill(req.user.id, game.id, symbol, metal.name, 'sell', oz, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  audit(req, 'METALS_SELL', `${oz} oz ${metal.name} @ $${quote.price.toFixed(2)}`);
  res.json({ filled: true, message: `Sold ${oz} oz of ${metal.name} at $${quote.price.toFixed(2)}/oz`, cash_balance: updated.cash_balance });
});

// ─── Forex ───────────────────────────────────────────────────────────────────

app.get('/api/forex/list', requireAuth, async (req, res) => {
  const enriched = await Promise.all(FOREX_PAIRS.map(async f => {
    try {
      const q = await getQuote(f.symbol);
      return { ...f, price: q.price, change: q.change, changePercent: q.changePercent, marketState: q.marketState };
    } catch {
      return { ...f, price: null, change: 0, changePercent: 0, marketState: 'CLOSED' };
    }
  }));
  res.json(enriched);
});

app.post('/api/games/:gameId/forex/buy', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_forex)         return res.status(400).json({ error: 'Forex trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });

  let { symbol, quantity } = req.body || {};
  symbol = symbol?.toUpperCase(); quantity = parseFloat(quantity);
  if (!symbol || isNaN(quantity) || quantity <= 0) return res.status(400).json({ error: 'symbol and positive quantity are required' });
  if (!validSymbol(symbol)) return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(quantity)) return res.status(400).json({ error: 'Quantity must be between 0 and 1,000,000' });

  const pair = FOREX_PAIRS.find(f => f.symbol === symbol);
  if (!pair) return res.status(400).json({ error: `${symbol} is not a supported forex pair` });

  let quote;
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch price — market data unavailable' }); }

  const portfolio = ensurePortfolio(req.user.id, game.id, game.starting_cash);
  const cost = +(quote.price * quantity).toFixed(6);
  if (!validTotal(cost)) return res.status(400).json({ error: 'Invalid cost calculation' });
  const avail = availableCash(req.user.id, game.id, portfolio);
  if (cost > avail) return res.status(400).json({ error: `Insufficient funds — cost $${cost.toFixed(2)}, available $${avail.toFixed(2)}` });

  applyFill(req.user.id, game.id, symbol, pair.name, 'buy', quantity, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  audit(req, 'FOREX_BUY', `${quantity} units ${pair.name} @ ${quote.price.toFixed(5)}`);
  res.json({ filled: true, message: `Bought ${quantity} units of ${pair.name} at ${quote.price.toFixed(5)}`, cash_balance: updated.cash_balance, total_cost: cost });
});

app.post('/api/games/:gameId/forex/sell', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_forex)         return res.status(400).json({ error: 'Forex trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended' });

  let { symbol, quantity } = req.body || {};
  symbol = symbol?.toUpperCase(); quantity = parseFloat(quantity);
  if (!symbol || isNaN(quantity) || quantity <= 0) return res.status(400).json({ error: 'symbol and positive quantity are required' });
  if (!validSymbol(symbol)) return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(quantity)) return res.status(400).json({ error: 'Quantity must be between 0 and 1,000,000' });

  const pair = FOREX_PAIRS.find(f => f.symbol === symbol);
  if (!pair) return res.status(400).json({ error: `${symbol} is not a supported forex pair` });

  const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(req.user.id, game.id, symbol);
  if (!holding || holding.shares < quantity - 0.000001)
    return res.status(400).json({ error: `Insufficient — you own ${holding ? holding.shares.toFixed(2) : 0} units of ${pair.name}` });

  let quote;
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch price — market data unavailable' }); }

  applyFill(req.user.id, game.id, symbol, pair.name, 'sell', quantity, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  audit(req, 'FOREX_SELL', `${quantity} units ${pair.name} @ ${quote.price.toFixed(5)}`);
  res.json({ filled: true, message: `Sold ${quantity} units of ${pair.name} at ${quote.price.toFixed(5)}`, cash_balance: updated.cash_balance });
});

// ─── Crypto ───────────────────────────────────────────────────────────────────

app.get('/api/crypto/list', requireAuth, async (req, res) => {
  const enriched = await Promise.all(CRYPTO_ASSETS.map(async c => {
    try {
      const q = await getQuote(c.symbol);
      return { ...c, price: q.price, change: q.change, changePercent: q.changePercent, marketState: q.marketState };
    } catch {
      return { ...c, price: null, change: 0, changePercent: 0, marketState: 'CLOSED' };
    }
  }));
  res.json(enriched);
});

app.post('/api/games/:gameId/crypto/buy', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_crypto)        return res.status(400).json({ error: 'Crypto trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended — no more trades' });

  let { symbol, quantity } = req.body || {};
  symbol = symbol?.toUpperCase(); quantity = parseFloat(quantity);
  if (!symbol || isNaN(quantity) || quantity <= 0) return res.status(400).json({ error: 'symbol and positive quantity are required' });
  if (!validSymbol(symbol)) return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(quantity)) return res.status(400).json({ error: 'Quantity must be between 0 and 1,000,000' });

  const asset = CRYPTO_ASSETS.find(c => c.symbol === symbol);
  if (!asset) return res.status(400).json({ error: `${symbol} is not a supported crypto asset` });

  let quote;
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch price — market data unavailable' }); }

  const portfolio = ensurePortfolio(req.user.id, game.id, game.starting_cash);
  const cost = +(quote.price * quantity).toFixed(6);
  if (!validTotal(cost)) return res.status(400).json({ error: 'Invalid cost calculation' });
  const avail = availableCash(req.user.id, game.id, portfolio);
  if (cost > avail) return res.status(400).json({ error: `Insufficient funds — cost $${cost.toFixed(2)}, available $${avail.toFixed(2)}` });

  applyFill(req.user.id, game.id, symbol, asset.name, 'buy', quantity, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  audit(req, 'CRYPTO_BUY', `${quantity} ${asset.name} @ $${quote.price.toFixed(2)}`);
  res.json({ filled: true, message: `Bought ${quantity} ${asset.name} at $${quote.price.toFixed(2)}`, cash_balance: updated.cash_balance, total_cost: cost });
});

app.post('/api/games/:gameId/crypto/sell', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  if (!game.allow_crypto)        return res.status(400).json({ error: 'Crypto trading is not enabled in this game' });
  if (game.status === 'pending') return res.status(400).json({ error: 'Game has not started yet' });
  if (game.status === 'ended')   return res.status(400).json({ error: 'Game has ended' });

  let { symbol, quantity } = req.body || {};
  symbol = symbol?.toUpperCase(); quantity = parseFloat(quantity);
  if (!symbol || isNaN(quantity) || quantity <= 0) return res.status(400).json({ error: 'symbol and positive quantity are required' });
  if (!validSymbol(symbol)) return res.status(400).json({ error: 'Invalid symbol format' });
  if (!validShares(quantity)) return res.status(400).json({ error: 'Quantity must be between 0 and 1,000,000' });

  const asset = CRYPTO_ASSETS.find(c => c.symbol === symbol);
  if (!asset) return res.status(400).json({ error: `${symbol} is not a supported crypto asset` });

  const holding = db.prepare('SELECT * FROM holdings WHERE user_id = ? AND game_id = ? AND symbol = ?').get(req.user.id, game.id, symbol);
  if (!holding || holding.shares < quantity - 0.000001)
    return res.status(400).json({ error: `Insufficient — you own ${holding ? holding.shares.toFixed(8) : 0} ${asset.name}` });

  let quote;
  try { quote = await getQuote(symbol); } catch { return res.status(400).json({ error: 'Unable to fetch price — market data unavailable' }); }

  applyFill(req.user.id, game.id, symbol, asset.name, 'sell', quantity, quote.price);
  const updated = db.prepare('SELECT * FROM portfolios WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);
  audit(req, 'CRYPTO_SELL', `${quantity} ${asset.name} @ $${quote.price.toFixed(2)}`);
  res.json({ filled: true, message: `Sold ${quantity} ${asset.name} at $${quote.price.toFixed(2)}`, cash_balance: updated.cash_balance });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ASSET CATALOGUE — unified list of everything tradeable in a game
// ═══════════════════════════════════════════════════════════════════════════════

// Returns all asset classes available in this game with live prices.
// Stocks are dynamically searchable (no fixed universe), so this returns
// guidance + endpoints rather than a full ticker list.
// Metals and futures are fixed catalogues — returned with live prices.
app.get('/api/games/:gameId/assets', requireAuth, loadGame, async (req, res) => {
  const game = req.game;
  const base  = `/api/games/${game.id}`;

  const priceEnrich = async (catalogue) => Promise.all(catalogue.map(async item => {
    try {
      const q = await getQuote(item.symbol);
      return { ...item, price: q.price, change: q.change, change_percent: q.changePercent, market_state: q.marketState };
    } catch {
      return { ...item, price: null, change: 0, change_percent: 0, market_state: 'CLOSED' };
    }
  }));

  const [metalsResult, futuresResult, forexResult, cryptoResult] = await Promise.allSettled([
    game.allow_metals  ? priceEnrich(PRECIOUS_METALS)   : Promise.resolve(null),
    game.allow_futures ? priceEnrich(FUTURES_CONTRACTS) : Promise.resolve(null),
    game.allow_forex   ? priceEnrich(FOREX_PAIRS)        : Promise.resolve(null),
    game.allow_crypto  ? priceEnrich(CRYPTO_ASSETS)      : Promise.resolve(null),
  ]);

  const metals  = metalsResult.status  === 'fulfilled' ? metalsResult.value  : null;
  const futures = futuresResult.status === 'fulfilled' ? futuresResult.value : null;
  const forex   = forexResult.status   === 'fulfilled' ? forexResult.value   : null;
  const crypto  = cryptoResult.status  === 'fulfilled' ? cryptoResult.value  : null;

  res.json({
    game: {
      id:               game.id,
      title:            game.title,
      status:           game.status,
      starting_cash:    game.starting_cash,
      allow_fractional: !!game.allow_fractional,
      allow_futures:    !!game.allow_futures,
      allow_metals:     !!game.allow_metals,
      allow_forex:      !!game.allow_forex,
      allow_crypto:     !!game.allow_crypto,
      markets:          game.markets,
    },

    stocks: {
      description: 'Any stock listed on the allowed exchanges. Use the search endpoint to find symbols, then the quote endpoint for live prices.',
      allowed_markets: game.markets,
      allow_fractional: !!game.allow_fractional,
      endpoints: {
        search:      '/api/stocks/search?q=<symbol_or_name>',
        quote:       '/api/stocks/quote/:symbol',
        chart:       '/api/stocks/chart/:symbol',
        buy:         `${base}/orders  POST  { symbol, type:"buy",  order_type:"market"|"limit", shares, limit_price? }`,
        sell:        `${base}/orders  POST  { symbol, type:"sell", order_type:"market"|"limit", shares, limit_price? }`,
        orders:      `${base}/orders  GET`,
        cancel:      `${base}/orders/:orderId  DELETE`,
      },
    },

    precious_metals: metals
      ? {
          description: 'Spot precious metals priced per troy ounce. Trade 24/5 — no market-hours restriction.',
          unit: 'troy oz',
          assets: metals,
          endpoints: {
            list:  '/api/metals/list',
            buy:   `${base}/metals/buy  POST  { symbol, oz }`,
            sell:  `${base}/metals/sell  POST  { symbol, oz }`,
          },
        }
      : { enabled: false },

    forex: forex
      ? {
          description: 'Spot forex currency pairs. Priced as quoted currency per base currency unit.',
          unit: 'units',
          assets: forex,
          endpoints: {
            list:  '/api/forex/list',
            buy:   `${base}/forex/buy  POST  { symbol, quantity }`,
            sell:  `${base}/forex/sell  POST  { symbol, quantity }`,
          },
        }
      : { enabled: false },

    crypto: crypto
      ? {
          description: 'Spot cryptocurrency assets. Trade 24/7 — no market-hours restriction.',
          unit: 'coins',
          assets: crypto,
          endpoints: {
            list:  '/api/crypto/list',
            buy:   `${base}/crypto/buy  POST  { symbol, quantity }`,
            sell:  `${base}/crypto/sell  POST  { symbol, quantity }`,
          },
        }
      : { enabled: false },

    futures: futures
      ? {
          description: 'Margin-based futures contracts. P&L = contracts × (exit − entry). Margin rate applies.',
          margin_rate:  game.futures_margin,
          assets: futures,
          endpoints: {
            list:      '/api/futures/contracts',
            positions: `${base}/futures/positions  GET`,
            open:      `${base}/futures/open   POST  { symbol, direction:"long"|"short", contracts }`,
            close:     `${base}/futures/close  POST  { symbol, contracts }`,
            history:   `${base}/futures/history  GET`,
          },
        }
      : { enabled: false },
  });
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
    res.status(500).json({ error: 'Failed to delete game' });
  }
});

// ── Admin — SMTP settings ─────────────────────────────────────────────────────
app.get('/api/admin/settings/smtp', requireAdmin, (req, res) => {
  const pass = getSetting('smtp_pass') || (process.env.SMTP_PASS ? '••••••••' : '');
  res.json({
    smtp_host:  getSetting('smtp_host')  || process.env.SMTP_HOST  || '',
    smtp_port:  getSetting('smtp_port')  || process.env.SMTP_PORT  || '587',
    smtp_user:  getSetting('smtp_user')  || process.env.SMTP_USER  || '',
    smtp_pass:  pass ? '••••••••' : '',   // never expose the real password
    email_from: getSetting('email_from') || process.env.EMAIL_FROM || '',
    base_url:   getSetting('base_url')   || process.env.BASE_URL   || `http://localhost:${PORT}`,
    enabled:    isEmailEnabled(),
  });
});

app.put('/api/admin/settings/smtp', requireAdmin, async (req, res) => {
  const { smtp_host, smtp_port, smtp_user, smtp_pass, email_from, base_url } = req.body || {};
  setSetting('smtp_host',  smtp_host  ?? '');
  setSetting('smtp_port',  smtp_port  ?? '587');
  setSetting('smtp_user',  smtp_user  ?? '');
  // Only overwrite password if a new one was supplied (not the masked placeholder)
  if (smtp_pass && smtp_pass !== '••••••••') setSetting('smtp_pass', encryptField(smtp_pass)); // stored encrypted
  setSetting('email_from', email_from ?? '');
  setSetting('base_url',   base_url   ?? '');

  const host = getSetting('smtp_host');
  const user = getSetting('smtp_user');
  const rawPass = getSetting('smtp_pass');
  const pass    = rawPass ? (decryptField(rawPass) ?? rawPass) : '';
  const port = getSetting('smtp_port');
  const from = getSetting('email_from');
  const url  = getSetting('base_url');
  audit(req, 'SMTP_SETTINGS_CHANGED');
  const result = await configureMailer({ host, port, user, pass, from, baseUrl: url });
  res.json({ message: result.ok ? 'SMTP settings saved and connection verified.' : `Settings saved — but connection failed: ${result.error}`, enabled: result.ok });
});

app.post('/api/admin/settings/smtp/test', requireAdmin, async (req, res) => {
  const { to } = req.body || {};
  if (!to) return res.status(400).json({ error: 'Provide a "to" email address for the test.' });
  if (!isEmailEnabled()) return res.status(503).json({ error: 'SMTP is not configured or not connected.' });
  const admin = db.prepare('SELECT username FROM users WHERE id = ?').get(req.user.id);
  const ok = await sendEmail(to, 'Test Email — StockArena SMTP Check', buildTestEmail(admin?.username || 'Admin'));
  ok ? res.json({ message: `Test email sent to ${to}` })
     : res.status(500).json({ error: 'Send failed — check server logs for SMTP error details.' });
});

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/players', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, username, email, is_admin, is_approved, created_at FROM users ORDER BY created_at').all());
});

app.post('/api/admin/users/:userId/approve', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').run(target.id);
  audit(req, 'USER_APPROVED', target.username);
  res.json({ message: `${target.username} has been approved.` });
});

app.post('/api/admin/users/:userId/revoke', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.is_admin) return res.status(400).json({ error: 'Cannot revoke approval from an admin account.' });
  db.prepare('UPDATE users SET is_approved = 0 WHERE id = ?').run(target.id);
  audit(req, 'USER_REVOKED', target.username);
  res.json({ message: `${target.username}'s approval has been revoked.` });
});

app.delete('/api/admin/users/:userId', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT id, username, is_admin, is_approved FROM users WHERE id = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.is_admin) return res.status(400).json({ error: 'Cannot delete an admin account.' });
  if (target.is_approved) return res.status(400).json({ error: 'Cannot delete an approved user. Revoke approval first, or delete via game management.' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account.' });
  db.transaction(() => {
    db.prepare('DELETE FROM futures_transactions WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM futures_positions    WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM pending_orders       WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM transactions         WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM holdings             WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM portfolios           WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM api_keys             WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM users                WHERE id = ?').run(target.id);
  })();
  audit(req, 'USER_DELETED', target.username);
  res.json({ message: `${target.username} has been deleted.` });
});

// ── Trade notification helper ─────────────────────────────────────────────────
async function fireTradeNotification(userId, gameId, symbol, companyName, type, shares, price, total) {
  try {
    const u = db.prepare('SELECT username, email, notify_trades FROM users WHERE id = ?').get(userId);
    if (!u?.notify_trades || !u.email || u.email.endsWith('@local')) return;
    const g = db.prepare('SELECT title FROM game_config WHERE id = ?').get(gameId);
    const p = db.prepare('SELECT cash_balance FROM portfolios WHERE user_id = ? AND game_id = ?').get(userId, gameId);
    await sendEmail(u.email,
      `Trade Confirmed: ${type.toUpperCase()} ${shares} × ${symbol} — StockArena`,
      buildTradeEmail({ username: u.username, gameName: g?.title || 'Game', type, symbol, companyName, shares, price, total, cashBalance: p?.cash_balance ?? 0 })
    );
  } catch (err) { console.error('[Email] trade notification failed:', err.message); }
}

// ── Background order processor ────────────────────────────────────────────────
async function fillOrder(order, cachedPrice = null) {
  const game = db.prepare('SELECT * FROM game_config WHERE id = ?').get(order.game_id);
  if (!game || gameStatus(game) !== 'active') {
    db.prepare("UPDATE pending_orders SET status='rejected', reject_reason='Game is no longer active', filled_at=datetime('now') WHERE id=?").run(order.id);
    return;
  }
  let price = cachedPrice;
  if (price == null) {
    try { price = (await getQuote(order.symbol)).price; }
    catch { return; } // price unavailable — try next cycle
  }

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
  fireTradeNotification(order.user_id, order.game_id, order.symbol, order.company_name, order.type, order.shares, price, total);
}

async function processAllPendingOrders() {
  const pending = db.prepare("SELECT * FROM pending_orders WHERE status='pending' ORDER BY submitted_at").all();
  if (!pending.length) return;
  const open = isMarketOpen();

  // Batch-fetch all unique symbols needed this cycle — avoids N sequential YF calls
  const neededSymbols = [...new Set(pending.map(o => o.symbol))];
  const batchPrices = {};
  await Promise.allSettled(neededSymbols.map(async sym => {
    try { batchPrices[sym] = (await getQuote(sym)).price; } catch {}
  }));

  for (const order of pending) {
    try {
      if (order.order_type === 'market') {
        if (open) await fillOrder(order, batchPrices[order.symbol]);
      } else {
        // Limit orders: check price condition (triggers at any hour for game realism)
        const price = batchPrices[order.symbol];
        if (price == null) continue;
        const triggered = order.type === 'buy'  ? price <= order.limit_price
                        : order.type === 'sell' ? price >= order.limit_price : false;
        if (triggered) await fillOrder(order, price);
      }
    } catch (err) {
      console.error(`[Orders] Error on order ${order.id}:`, err.message);
    }
  }
}

// ── Daily email scheduler ─────────────────────────────────────────────────────
let lastDailyEmailDate = '';

async function sendDailyEmails() {
  if (!isEmailEnabled()) return;
  const users = db.prepare(
    'SELECT id, username, email, notify_daily, notify_ranking FROM users WHERE is_approved = 1 AND (notify_daily = 1 OR notify_ranking = 1)'
  ).all().filter(u => u.email && !u.email.endsWith('@local'));
  if (!users.length) return;
  console.log(`[Email] Sending daily summaries to ${users.length} user(s)…`);
  const today = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

  // ── Pre-compute per-game leaderboard and prices ONCE for all users ───────────
  const activeGames = db.prepare('SELECT * FROM game_config WHERE is_active = 1').all();
  const gameCache = {}; // gameId → { priceMap, ranked }

  await Promise.allSettled(activeGames.map(async game => {
    const allHoldings = db.prepare('SELECT * FROM holdings WHERE game_id = ? AND shares > 0').all(game.id);
    const allFutures  = game.allow_futures
      ? db.prepare('SELECT * FROM futures_positions WHERE game_id = ? AND contracts > 0').all(game.id) : [];
    const symbols = [...new Set([...allHoldings.map(h => h.symbol), ...allFutures.map(f => f.symbol)])];

    const priceMap = {};
    await Promise.allSettled(symbols.map(async sym => {
      try { priceMap[sym] = (await getQuote(sym)).price; } catch {}
    }));

    const allPortfolios = db.prepare('SELECT user_id, cash_balance FROM portfolios WHERE game_id = ?').all(game.id);
    const ranked = allPortfolios.map(ap => {
      const sv = allHoldings.filter(h => h.user_id === ap.user_id)
        .reduce((s, h) => s + h.shares * (priceMap[h.symbol] ?? h.avg_cost), 0);
      const fp = allFutures.filter(f => f.user_id === ap.user_id)
        .reduce((s, f) => s + (f.direction === 'long' ? (priceMap[f.symbol] ?? f.entry_price) - f.entry_price : f.entry_price - (priceMap[f.symbol] ?? f.entry_price)) * f.contracts, 0);
      return { user_id: ap.user_id, total: ap.cash_balance + sv + fp };
    }).sort((a, b) => b.total - a.total);

    gameCache[game.id] = { game, priceMap, ranked, allHoldings };
  }));

  // ── Send each user's email using cached data ──────────────────────────────────
  for (const u of users) {
    try {
      const portfolios = db.prepare(
        'SELECT p.*, g.title, g.starting_cash, g.allow_futures FROM portfolios p JOIN game_config g ON p.game_id = g.id WHERE p.user_id = ? AND g.is_active = 1'
      ).all(u.id);
      if (!portfolios.length) continue;

      const gameData = portfolios.map(p => {
        const cached = gameCache[p.game_id];
        if (!cached) return null;
        const { priceMap, ranked, allHoldings } = cached;
        const userHoldings = allHoldings.filter(h => h.user_id === u.id).map(h => ({ ...h, current_price: priceMap[h.symbol] ?? h.avg_cost }));
        const stockValue   = userHoldings.reduce((s, h) => s + h.shares * h.current_price, 0);
        const rank = (ranked.findIndex(r => r.user_id === u.id) + 1) || ranked.length + 1;
        const totalValue = p.cash_balance + stockValue;
        return { gameName: p.title, totalValue, startingCash: p.starting_cash, cashBalance: p.cash_balance, stockValue, futuresPnl: 0, rank, totalPlayers: ranked.length, holdings: userHoldings };
      }).filter(Boolean);

      if (!gameData.length) continue;

      if (u.notify_daily) {
        await sendEmail(u.email, `Daily Summary — ${today} — StockArena`, buildDailySummaryEmail({ username: u.username, date: today, games: gameData }));
      } else if (u.notify_ranking) {
        for (const g of gameData) {
          const gain = g.totalValue - g.startingCash;
          await sendEmail(u.email, `You're ranked #${g.rank} in "${g.gameName}" — StockArena`,
            buildRankingEmail({ username: u.username, gameName: g.gameName, rank: g.rank, totalPlayers: g.totalPlayers, totalValue: g.totalValue, gain, gainPct: (gain / g.startingCash) * 100 }));
        }
      }
    } catch (err) { console.error(`[Email] daily summary for ${u.username} failed:`, err.message); }
  }
  console.log('[Email] Daily summaries complete.');
}

async function maybeRunDailyEmails() {
  const { weekday, hour, minute } = getEasternParts();
  if (weekday === 'Sat' || weekday === 'Sun') return;
  const todayKey = new Date().toISOString().split('T')[0];
  if (lastDailyEmailDate === todayKey) return;
  // Fire after 4:15 PM ET (15 min buffer after market close)
  if (hour * 60 + minute >= 975) {
    lastDailyEmailDate = todayKey;
    await sendDailyEmails();
  }
}

// Run immediately at startup then every 60 s
processAllPendingOrders();
setInterval(async () => {
  await processAllPendingOrders();
  await maybeRunDailyEmails();
}, 60_000);

// ═══════════════════════════════════════════════════════════════════════════════
// SOFTWARE UPDATE (admin only)
// ═══════════════════════════════════════════════════════════════════════════════

function gitRun(cmd) {
  return execSync(`git -C "${__dirname}" ${cmd}`, { encoding: 'utf8', timeout: 30_000 }).trim();
}

// Check if there are updates available (runs git fetch)
app.get('/api/admin/update/status', requireAdmin, (req, res) => {
  try {
    if (!fs_existsSync(path.join(__dirname, '.git')))
      return res.status(400).json({ error: 'Not a git repository — auto-update unavailable' });
    gitRun('fetch origin --quiet');
    const branch     = gitRun('rev-parse --abbrev-ref HEAD');
    const currentSha = gitRun('rev-parse HEAD');
    const remoteSha  = gitRun(`rev-parse origin/${branch}`);
    const upToDate   = currentSha === remoteSha;
    const changelog  = upToDate ? [] : gitRun(`log --oneline HEAD..origin/${branch}`).split('\n').filter(Boolean).slice(0, 30);
    res.json({ up_to_date: upToDate, current_short: currentSha.slice(0, 7), remote_short: remoteSha.slice(0, 7), branch, changelog });
  } catch (err) {
    res.status(500).json({ error: `Git check failed: ${err.message.split('\n')[0]}` });
  }
});

// Apply update via SSE stream — EventSource can't set headers so we accept JWT in query string
app.get('/api/admin/update/apply', (req, res) => {
  // Manually validate the JWT from query string
  const raw = req.query.token;
  if (!raw) return res.status(401).end();
  let payload;
  try { payload = jwt.verify(raw, JWT_SECRET); } catch { return res.status(401).end(); }
  if (isBlacklisted(payload.jti)) return res.status(401).end();
  const dbUser = db.prepare('SELECT username, is_admin FROM users WHERE id = ?').get(payload.id);
  if (!dbUser?.is_admin) return res.status(403).end();

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const send = (type, data) => { try { res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`); } catch {} };
  const log  = msg  => send('log', { msg });
  const done = (ok, msg) => { send('done', { success: ok, msg }); res.end(); };

  console.log(`[AUDIT] ${new Date().toISOString()} ${dbUser.username} — APPLY_UPDATE`);

  try {
    if (!fs_existsSync(path.join(__dirname, '.git')))
      return done(false, 'Not a git repository — cannot update');

    const branch     = gitRun('rev-parse --abbrev-ref HEAD');
    const currentSha = gitRun('rev-parse HEAD');
    log(`Current version : ${currentSha.slice(0, 7)}  (branch: ${branch})`);

    log('Fetching latest code from GitHub…');
    gitRun('fetch origin --quiet');

    const remoteSha = gitRun(`rev-parse origin/${branch}`);
    if (currentSha === remoteSha) {
      return done(true, 'Already up to date — no restart needed.');
    }

    const changelog = gitRun(`log --oneline HEAD..origin/${branch}`).split('\n').filter(Boolean);
    log(`${changelog.length} new commit${changelog.length !== 1 ? 's' : ''}:`);
    changelog.forEach(line => log(`  ${line}`));

    log(`\nApplying update…`);
    gitRun(`reset --hard origin/${branch}`);
    const newSha = gitRun('rev-parse --short HEAD');
    log(`Updated to ${newSha}`);

    // Re-install deps only if package.json changed
    try {
      const changed = gitRun(`diff --name-only ${currentSha} HEAD`);
      if (changed.includes('package.json')) {
        log('package.json changed — running npm install…');
        execSync('npm install --omit=dev --silent', { cwd: __dirname, timeout: 120_000, encoding: 'utf8' });
        log('Dependencies updated.');
      } else {
        log('Dependencies unchanged — skipping npm install.');
      }
    } catch (npmErr) {
      log(`Warning: npm install failed — ${npmErr.message.split('\n')[0]}`);
    }

    log('\nRestarting server…');
    done(true, `Updated to ${newSha}. Server is restarting — reconnect in a few seconds.`);
    setTimeout(() => process.exit(0), 500);
  } catch (err) {
    done(false, `Update failed: ${err.message.split('\n')[0]}`);
  }
});

// ── Catch-all → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Global error handler — catches any unhandled throw in route handlers ──────
app.use((err, req, res, _next) => {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
  if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`\n  StockArena running at http://0.0.0.0:${PORT}\n`));
