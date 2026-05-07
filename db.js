const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'stockgame.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS game_config (
    id          INTEGER PRIMARY KEY,
    title       TEXT    NOT NULL DEFAULT 'Stock Trading Game',
    start_date  TEXT    NOT NULL,
    end_date    TEXT    NOT NULL,
    starting_cash REAL  NOT NULL DEFAULT 10000,
    markets     TEXT    NOT NULL DEFAULT '["NYSE","NASDAQ"]',
    allow_fractional INTEGER NOT NULL DEFAULT 1,
    is_active   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS portfolios (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    game_id      INTEGER NOT NULL,
    cash_balance REAL    NOT NULL,
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
`);

module.exports = db;
