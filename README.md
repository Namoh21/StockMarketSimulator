# 📈 StockArena — Stock Trading Simulation Game

A real-time stock trading simulation you can self-host for friends and groups. Players compete to grow a simulated portfolio using live market data, with support for multiple simultaneous games, futures contracts, limit orders, email notifications, and an AI agent API.

> **This is a game. No real money is involved. All prices are simulated using publicly available market data.**

---

## Features

### Trading
- **Live stock data** via Yahoo Finance (2-minute cache, auto-refreshes every 30 seconds)
- **Buy / Sell** by symbol or company name search with typeahead
- **Market & limit orders** — limit orders queue and fill automatically when the price is hit
- **Fractional shares** (optional, admin-configurable)
- **Futures trading** — long/short contracts on major indices and commodities with configurable margin
- **Balance enforcement** — reserved funds lock when a pending buy order is queued, preventing overspending
- **30-day price chart** per stock

### Multi-Game Support
- **Multiple simultaneous games** — each with its own starting cash, date range, markets, and leaderboard
- **Public & private games** — private games require a join password
- **Per-game leaderboard** ranked by total portfolio value (cash + holdings + futures P&L)
- **Admin can remove players** from individual games without deleting their account

### User Management
- **Registration approval flow** — new accounts are held pending until an admin approves them
- **Admin approval panel** — approve or reject pending registrations
- **Role system** — first registered user is automatically admin

### AI Agent API
- **API key generation** — users can create `ska_`-prefixed keys for programmatic trading
- Keys are SHA-256 hashed at rest and shown only once at creation
- AI agents can read portfolio state, quotes, and submit trades on behalf of the user

### Email Notifications (optional)
- **Trade confirmations** — email on every filled buy/sell
- **Daily portfolio summary** — end-of-day snapshot with holdings P&L and leaderboard rank
- **Ranking alerts** — notify when rank changes
- Configured via the Admin tab (Brevo / any SMTP relay); SMTP password stored AES-256-GCM encrypted

### Admin Panel
- Create and manage multiple game sessions
- Configure start/end dates, starting cash, allowed markets, fractional shares, and futures
- SMTP email setup with connection test
- Approve/reject/delete pending users
- Per-game player management

### Security
- JWT authentication with per-token blacklist (persistent across restarts)
- bcrypt password hashing
- AES-256-GCM encryption for sensitive fields at rest (SMTP password, game join passwords)
- Rate limiting on login, registration, and join-game attempts
- Rate-limit violations logged to audit trail
- Timing-safe comparison for join passwords
- Input validation and parameterized queries throughout (no SQL injection surface)
- CORS restricted to configured `BASE_URL`

---

## Requirements

- **Node.js 18+**
- **npm**
- **Internet connection** (for Yahoo Finance market data)

---

## Quick Start

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

**One-liner install** — clones the repo, installs Node.js, and creates a systemd service that starts on boot:

```bash
curl -fsSL https://raw.githubusercontent.com/Namoh21/StockMarketSimulator/main/install.sh | bash
```

Or manually:

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3 git curl

# Install Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

git clone https://github.com/Namoh21/StockMarketSimulator ~/StockMarketSimulator
cd ~/StockMarketSimulator
npm install
npm start
```

The server binds to `0.0.0.0:8081`. Share your Pi's local IP with players:

```
http://192.168.x.x:8081
```

### Service management

```bash
sudo systemctl status stockarena     # check status
sudo journalctl -u stockarena -f     # live logs
sudo systemctl restart stockarena    # restart
```

### Update to latest version

```bash
cd ~/StockMarketSimulator
bash update.sh
```

Or manually:

```bash
git pull && npm install && sudo systemctl restart stockarena
```

---

## First-Time Setup

1. Open the app and **register an account** — the first registration automatically becomes admin
2. Go to **⚙ Admin → Games** and create a game:
   - Set a title, start/end dates, starting cash, and allowed markets
   - Optionally enable futures trading and set a margin requirement
   - Optionally make the game private (password-protected)
3. Share the URL with players — they register and join the game

---

## Environment Variables

| Variable      | Default                           | Description                                        |
|---------------|-----------------------------------|----------------------------------------------------|
| `PORT`        | `8081`                            | HTTP server port                                   |
| `JWT_SECRET`  | *(insecure default)*              | **Change this.** Used for JWT signing and field encryption |
| `BASE_URL`    | `http://localhost:8081`           | Public URL — used in CORS policy and email links   |

```bash
# Example
JWT_SECRET=a-long-random-secret BASE_URL=http://192.168.1.50:8081 npm start
```

> **Important:** Set a strong, unique `JWT_SECRET` before sharing with others. This value also derives the encryption key used to protect SMTP passwords and game join passwords stored in the database.

---

## Game Rules

- Each player starts with the configured starting cash
- Buy and sell any stock on the allowed exchanges using live market prices
- Prices are fetched from Yahoo Finance and cached for 2 minutes
- Trades execute immediately when the market is open (9:30 AM – 4:00 PM ET, Mon–Fri)
- Orders placed outside market hours queue as pending and execute at the next open
- Limit orders queue until the target price is reached, then fill automatically
- The player with the highest total portfolio value at game end wins
- Futures positions are marked to market using live prices; unrealized P&L counts toward total value

---

## Project Structure

```
├── server.js        — Express server, all API routes, background order processor, email scheduler
├── db.js            — SQLite schema, migrations, and index definitions
├── email.js         — Nodemailer transport, email template builders
├── package.json
├── install.sh       — Raspberry Pi one-liner installer
├── update.sh        — Pull latest changes and restart the service
├── stockgame.db     — Created automatically on first run (do not commit)
└── public/
    └── index.html   — Single-page application (vanilla HTML/CSS/JS, no build step)
```

---

## API Overview

Authentication uses **Bearer tokens** (JWT) obtained from `/api/auth/login`, or an **API key** (`Authorization: Bearer ska_...`) for agent access.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | — | Register new account |
| POST | `/api/auth/login` | — | Log in, receive JWT |
| POST | `/api/auth/logout` | ✓ | Invalidate current token |
| GET | `/api/auth/me` | ✓ | Current user info |
| GET | `/api/games` | ✓ | List available games |
| POST | `/api/games` | Admin | Create a game |
| GET | `/api/games/:id` | ✓ | Game details |
| POST | `/api/games/:id/join` | ✓ | Join a game |
| GET | `/api/games/:id/leaderboard` | ✓ | Ranked standings |
| GET | `/api/games/:id/portfolio` | ✓ | User's portfolio |
| POST | `/api/games/:id/buy` | ✓ | Buy shares |
| POST | `/api/games/:id/sell` | ✓ | Sell shares |
| GET | `/api/games/:id/transactions` | ✓ | Trade history |
| GET | `/api/games/:id/orders` | ✓ | Pending orders |
| DELETE | `/api/games/:id/orders/:orderId` | ✓ | Cancel a pending order |
| POST | `/api/games/:id/futures/open` | ✓ | Open a futures position |
| POST | `/api/games/:id/futures/close` | ✓ | Close a futures position |
| GET | `/api/market/status` | ✓ | Market open/closed status |
| GET | `/api/market/search?q=` | ✓ | Search stocks |
| GET | `/api/market/quote/:symbol` | ✓ | Live quote |
| GET | `/api/market/chart/:symbol` | ✓ | 30-day price chart |
| POST | `/api/user/api-keys` | ✓ | Create an API key |
| DELETE | `/api/user/api-keys/:id` | ✓ | Revoke an API key |
| GET | `/api/admin/users` | Admin | List all users |
| POST | `/api/admin/users/:id/approve` | Admin | Approve a pending user |
| DELETE | `/api/admin/users/:id` | Admin | Delete a pending user |

---

## Email Notifications (Optional)

StockArena can send email via any SMTP relay. The free tier of [Brevo](https://www.brevo.com/) (300 emails/day) works well for small groups.

1. Create a free Brevo account and generate an SMTP key
2. In the app, go to **⚙ Admin → Email / SMTP**
3. Enter your SMTP host (`smtp-relay.brevo.com`), port (`587`), username, and password
4. Click **Test Connection** to verify
5. Users opt in to notifications in their **Profile → Notifications** tab

---

## Disclaimer

**StockArena is a simulation game intended for educational and entertainment purposes only.**

- **No real money is involved.** All trading uses simulated currency. Nothing in this application constitutes financial advice, investment advice, or a recommendation to buy or sell any security.
- **Market data is provided by Yahoo Finance** via their public API and may be delayed, inaccurate, or unavailable. This project is not affiliated with, endorsed by, or sponsored by Yahoo Inc. or any stock exchange.
- **Not a licensed financial product.** This software is not registered with any financial regulatory authority (SEC, FINRA, FCA, or otherwise) and must not be used to simulate real investment decisions.
- **Self-hosted — you are responsible for your deployment.** The operator (the person running the server) is responsible for securing their instance, managing user data, and complying with applicable laws in their jurisdiction, including data protection regulations (GDPR, CCPA, etc.).
- **No warranty.** This software is provided "as is", without warranty of any kind, express or implied. The authors are not liable for any loss, damage, or legal liability arising from the use or misuse of this software.
- **User data.** This application stores usernames, bcrypt-hashed passwords, and portfolio history in a local SQLite database. No data is transmitted to third parties except for stock quote requests sent to Yahoo Finance's public API.

---

## License

This project is licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE) for the full text.

Key terms of GPL v3:
- You are free to use, copy, modify, and distribute this software
- Any modified version you distribute **must also be released under GPL v3**
- You must make the source code available to anyone who receives the software
- This software comes with **no warranty**

---

## Support

If you enjoy StockArena, donations are appreciated and help keep the project going!

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-yellow?logo=buy-me-a-coffee&logoColor=white)](https://buymeacoffee.com/Namoh21)

👉 **[buymeacoffee.com/Namoh21](https://buymeacoffee.com/Namoh21)**

---

## Contributing

This is a personal project. Issues and pull requests are welcome but may not be reviewed promptly.
