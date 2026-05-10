import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database(path.join(__dirname, 'stockgame.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS game_config (
    id               INTEGER PRIMARY KEY,
    title            TEXT    NOT NULL DEFAULT 'Stock Trading Game',
    start_date       TEXT    NOT NULL,
    end_date         TEXT    NOT NULL,
    starting_cash    REAL    NOT NULL DEFAULT 10000,
    markets          TEXT    NOT NULL DEFAULT '["NYSE","NASDAQ"]',
    allow_fractional INTEGER NOT NULL DEFAULT 1,
    allow_futures    INTEGER NOT NULL DEFAULT 0,
    futures_margin   REAL    NOT NULL DEFAULT 0.20,
    is_active        INTEGER NOT NULL DEFAULT 1,
    is_private       INTEGER NOT NULL DEFAULT 0,
    join_password    TEXT,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    is_approved   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS portfolios (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    game_id      INTEGER NOT NULL,
    cash_balance REAL    NOT NULL,
    joined_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, game_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (game_id) REFERENCES game_config(id)
  );

  CREATE TABLE IF NOT EXISTS holdings (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    game_id      INTEGER NOT NULL,
    symbol       TEXT    NOT NULL,
    company_name TEXT    NOT NULL DEFAULT '',
    shares       REAL    NOT NULL DEFAULT 0,
    avg_cost     REAL    NOT NULL DEFAULT 0,
    UNIQUE(user_id, game_id, symbol),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (game_id) REFERENCES game_config(id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    game_id      INTEGER NOT NULL,
    symbol       TEXT    NOT NULL,
    company_name TEXT    NOT NULL DEFAULT '',
    type         TEXT    NOT NULL CHECK(type IN ('buy','sell')),
    shares       REAL    NOT NULL,
    price        REAL    NOT NULL,
    total        REAL    NOT NULL,
    executed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (game_id) REFERENCES game_config(id)
  );

  CREATE TABLE IF NOT EXISTS futures_positions (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    game_id      INTEGER NOT NULL,
    symbol       TEXT    NOT NULL,
    name         TEXT    NOT NULL DEFAULT '',
    direction    TEXT    NOT NULL CHECK(direction IN ('long','short')),
    contracts    REAL    NOT NULL DEFAULT 0   CHECK(contracts >= 0),
    entry_price  REAL    NOT NULL             CHECK(entry_price > 0),
    margin_held  REAL    NOT NULL DEFAULT 0   CHECK(margin_held >= 0),
    opened_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, game_id, symbol),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (game_id) REFERENCES game_config(id)
  );

  CREATE TABLE IF NOT EXISTS futures_transactions (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    game_id      INTEGER NOT NULL,
    symbol       TEXT    NOT NULL,
    name         TEXT    NOT NULL DEFAULT '',
    direction    TEXT    NOT NULL CHECK(direction IN ('long','short')),
    action       TEXT    NOT NULL CHECK(action IN ('open','add','close')),
    contracts    REAL    NOT NULL,
    price        REAL    NOT NULL,
    margin_used  REAL    NOT NULL DEFAULT 0,
    realized_pnl REAL    NOT NULL DEFAULT 0,
    executed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (game_id) REFERENCES game_config(id)
  );

  CREATE TABLE IF NOT EXISTS server_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT    PRIMARY KEY,
    revoked_at TEXT    NOT NULL DEFAULT (datetime('now')),
    exp        INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    label      TEXT    NOT NULL DEFAULT 'AI Agent',
    key_value  TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used  TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS pending_orders (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL,
    game_id       INTEGER NOT NULL,
    symbol        TEXT    NOT NULL,
    company_name  TEXT    NOT NULL DEFAULT '',
    type          TEXT    NOT NULL CHECK(type IN ('buy','sell')),
    order_type    TEXT    NOT NULL CHECK(order_type IN ('market','limit')),
    shares        REAL    NOT NULL,
    limit_price   REAL,
    status        TEXT    NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','filled','cancelled','rejected')),
    reject_reason TEXT,
    submitted_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    filled_at     TEXT,
    filled_price  REAL,
    filled_total    REAL,
    reserved_amount REAL NOT NULL DEFAULT 0 CHECK(reserved_amount >= 0),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (game_id) REFERENCES game_config(id)
  );
`);

// Safe migrations for existing databases — silently skip if column already exists
const migrations = [
  "ALTER TABLE game_config    ADD COLUMN allow_futures    INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE game_config    ADD COLUMN futures_margin   REAL    NOT NULL DEFAULT 0.20",
  "ALTER TABLE game_config    ADD COLUMN is_active        INTEGER NOT NULL DEFAULT 1",
  "ALTER TABLE portfolios     ADD COLUMN joined_at        TEXT    NOT NULL DEFAULT (datetime('now'))",
  "ALTER TABLE pending_orders ADD COLUMN reserved_amount  REAL    NOT NULL DEFAULT 0",
  "ALTER TABLE users          ADD COLUMN is_approved      INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE game_config    ADD COLUMN is_private       INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE game_config    ADD COLUMN join_password    TEXT",
  "ALTER TABLE users          ADD COLUMN notify_trades    INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE users          ADD COLUMN notify_daily     INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE users          ADD COLUMN notify_ranking   INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE api_keys       ADD COLUMN key_hash         TEXT",
  "ALTER TABLE api_keys       ADD COLUMN key_preview      TEXT",
];
for (const sql of migrations) { try { db.exec(sql); } catch {} }

// Migrate: create revoked_tokens table if missing (was omitted from initial schema on some installs)
try {
  db.exec(`CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT    PRIMARY KEY,
    revoked_at TEXT    NOT NULL DEFAULT (datetime('now')),
    exp        INTEGER NOT NULL
  )`);
} catch {}

// Migrate: old schema had is_active=0 on deactivated games; set all existing to active=1
// so they show up in the new multi-game lobby (admin can deactivate manually if desired)
try {
  const count = db.prepare("SELECT COUNT(*) as c FROM game_config WHERE is_active = 1").get().c;
  if (count === 0) db.prepare("UPDATE game_config SET is_active = 1").run();
} catch {}

// Migrate: approve all pre-existing users so nobody gets locked out on upgrade
try { db.prepare("UPDATE users SET is_approved = 1 WHERE is_approved = 0").run(); } catch {}

// ── Indexes — created AFTER migrations so all columns exist ──────────────────
// Each index is individually wrapped so a missing column never crashes startup.
const _indexes = [
  'CREATE INDEX IF NOT EXISTS idx_portfolios_user_game   ON portfolios(user_id, game_id)',
  'CREATE INDEX IF NOT EXISTS idx_holdings_user_game     ON holdings(user_id, game_id)',
  'CREATE INDEX IF NOT EXISTS idx_holdings_game_shares   ON holdings(game_id, shares)',
  'CREATE INDEX IF NOT EXISTS idx_transactions_user_game ON transactions(user_id, game_id)',
  'CREATE INDEX IF NOT EXISTS idx_pending_orders_status  ON pending_orders(status, game_id)',
  'CREATE INDEX IF NOT EXISTS idx_futures_pos_user_game  ON futures_positions(user_id, game_id)',
  'CREATE INDEX IF NOT EXISTS idx_futures_tx_user_game   ON futures_transactions(user_id, game_id)',
  'CREATE INDEX IF NOT EXISTS idx_api_keys_user          ON api_keys(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_api_keys_hash          ON api_keys(key_hash)',
  'CREATE INDEX IF NOT EXISTS idx_server_settings_key    ON server_settings(key)',
  'CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp     ON revoked_tokens(exp)',
];
for (const sql of _indexes) { try { db.exec(sql); } catch {} }

export default db;
