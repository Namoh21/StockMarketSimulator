# 📈 StockArena — Stock Trading Simulation Game

A real-time stock trading game you can host for friends. Players compete to grow a simulated portfolio using live market data from Yahoo Finance.

---

## Features

- **Real stock data** via Yahoo Finance (5-minute cache)
- **User accounts** — register & sign in, first user is auto-admin
- **Buy / Sell** by symbol or company name search
- **Balance enforcement** — can't spend more than you have
- **Fractional shares** (optional, admin-configurable)
- **Market filtering** — NYSE, NASDAQ, AMEX, or All
- **Live leaderboard** ranked by total portfolio value
- **Transaction history**
- **30-day price chart** per stock
- **Admin panel** to configure game start/end dates, starting cash, and markets

---

## Requirements

- **Node.js 18+**
- **npm**
- **Internet connection** (for Yahoo Finance data)

---

## Quick Start (any platform)

```bash
# 1. Install dependencies (compiles native SQLite bindings)
npm install

# 2. Start the server
npm start

# 3. Open in browser
#    http://localhost:8081
```

---

## Raspberry Pi Setup

**One-liner install** (clones the repo, installs Node.js, sets up a systemd service that starts on boot):

```bash
curl -fsSL https://raw.githubusercontent.com/Namoh21/StockMarketSimulator/main/install.sh | bash
```

Or clone and run manually:

```bash
# Install build tools (needed for better-sqlite3)
sudo apt-get update
sudo apt-get install -y build-essential python3 git curl

# Install Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Clone the repo
git clone https://github.com/Namoh21/StockMarketSimulator ~/StockMarketSimulator
cd ~/StockMarketSimulator
npm install
npm start
```

The server binds to `0.0.0.0:8081`. Share your Pi's local IP with friends:
```
http://192.168.x.x:8081
```

### Service management (after install.sh)
```bash
sudo systemctl status stockarena    # check status
sudo journalctl -u stockarena -f    # live logs
sudo systemctl restart stockarena   # restart
```

### Update to latest version
```bash
cd ~/StockMarketSimulator && git pull && npm install --omit=dev && sudo systemctl restart stockarena
```

---

## First-Time Setup

1. Open the app and **register an account** — the first registration automatically becomes **admin**
2. Click **⚙ Admin** in the navbar
3. Fill in:
   - **Game Title** (e.g. "March Madness Trading")
   - **Start Date** and **End Date**
   - **Starting Cash** (e.g. $10,000)
   - **Allowed Markets** (NYSE, NASDAQ, AMEX, or All)
4. Click **Save & Start New Game**
5. Share the URL — friends register and start trading!

---

## Environment Variables

| Variable     | Default                          | Description                   |
|--------------|----------------------------------|-------------------------------|
| `PORT`       | `8081`                           | Server port                   |
| `JWT_SECRET` | `stockarena-change-this-secret…` | Change this for security!     |

```bash
# Example: start with custom secret and port
JWT_SECRET=my-super-secret PORT=8081 npm start
```

---

## Game Rules

- Each player starts with the configured amount of cash
- Buy and sell any stock on the allowed exchanges using real market prices  
- Prices are fetched live from Yahoo Finance (cached for 5 minutes)
- Trading is only allowed between the game's start and end dates
- The player with the highest total portfolio value at the end wins
- Fractional shares can be enabled/disabled by the admin

---

## Project Structure

```
├── server.js       — Express server + all API routes
├── db.js           — SQLite schema & initialization
├── package.json
├── stockgame.db    — Created automatically on first run
└── public/
    └── index.html  — Single-page app (HTML + CSS + JS)
```

---

## API Endpoints

| Method | Path                    | Auth  | Description              |
|--------|-------------------------|-------|--------------------------|
| POST   | /api/auth/register      | —     | Register new user        |
| POST   | /api/auth/login         | —     | Log in                   |
| GET    | /api/auth/me            | ✓     | Get current user         |
| GET    | /api/game/config        | —     | Get game configuration   |
| POST   | /api/game/config        | Admin | Create / update game     |
| GET    | /api/game/leaderboard   | ✓     | Get ranked standings     |
| GET    | /api/game/players       | Admin | List all players         |
| GET    | /api/stocks/search?q=   | —     | Search stocks            |
| GET    | /api/stocks/quote/:sym  | —     | Get live quote           |
| GET    | /api/stocks/chart/:sym  | —     | Get 30-day price history |
| GET    | /api/portfolio          | ✓     | Get user's portfolio     |
| POST   | /api/trades/buy         | ✓     | Buy shares               |
| POST   | /api/trades/sell        | ✓     | Sell shares              |
| GET    | /api/trades/history     | ✓     | Transaction history      |
