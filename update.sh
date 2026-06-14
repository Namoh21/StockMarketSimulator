#!/usr/bin/env bash
# ============================================================
#  StockArena — Update Script
#  Pulls the latest code from GitHub, updates dependencies,
#  and restarts the service. Never touches stockgame.db or .env
#
#  Usage:  bash update.sh
# ============================================================
set -e

SERVICE_NAME="stockarena"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_FILE="$INSTALL_DIR/stockgame.db"
ENV_FILE="$INSTALL_DIR/.env"
BACKUP_DIR="$HOME/stockarena-backups"

# ── Colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${B}[INFO]${N}  $*"; }
success() { echo -e "${G}[OK]${N}    $*"; }
warn()    { echo -e "${Y}[WARN]${N}  $*"; }
error()   { echo -e "${R}[ERROR]${N} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${C}▶ $*${N}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║      📈  StockArena Updater                  ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${N}"

# ── Sanity checks ─────────────────────────────────────────────────────────────
step "Pre-flight checks"

# Don't run the whole script as root: git/npm would then write files owned by
# root, which the stockarena service (running as a normal user) can't update
# later — breaking the in-app "Check for updates" feature with a
# "insufficient permission for adding an object to repository database" error.
# The two commands that need elevation (systemctl, copying the service unit)
# already call sudo themselves.
if [[ "$EUID" -eq 0 ]]; then
    error "Don't run this with sudo/as root — run 'bash update.sh' instead. (sudo is only needed for systemctl/service-file steps, which this script invokes itself.)"
fi

[[ -f "$INSTALL_DIR/server.js" ]] || error "server.js not found in $INSTALL_DIR — run from the project root."
[[ -d "$INSTALL_DIR/.git" ]]     || error "Not a git repository. Cannot update."
command -v node &>/dev/null      || error "Node.js not found. Re-run install.sh."
command -v npm  &>/dev/null      || error "npm not found. Re-run install.sh."

CURRENT_VERSION=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
info "Current version : $CURRENT_VERSION"
info "Install dir     : $INSTALL_DIR"
info "Database        : $DB_FILE"

# ── Backup database ───────────────────────────────────────────────────────────
step "Backing up database"
if [[ -f "$DB_FILE" ]]; then
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    BACKUP_FILE="$BACKUP_DIR/stockgame_${TIMESTAMP}.db"
    cp "$DB_FILE" "$BACKUP_FILE"
    success "Database backed up → $BACKUP_FILE"

    # Keep only the 10 most recent backups
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/stockgame_*.db 2>/dev/null | wc -l)
    if [[ "$BACKUP_COUNT" -gt 10 ]]; then
        ls -1t "$BACKUP_DIR"/stockgame_*.db | tail -n +11 | xargs rm -f
        info "Pruned old backups (kept 10 most recent)"
    fi
else
    warn "No database found yet — nothing to back up"
fi

# ── Pull latest code ──────────────────────────────────────────────────────────
step "Fetching latest code from GitHub"
git -C "$INSTALL_DIR" fetch origin

BRANCH=$(git -C "$INSTALL_DIR" rev-parse --abbrev-ref origin/HEAD 2>/dev/null | sed 's|origin/||' || echo "main")
LOCAL=$(git -C "$INSTALL_DIR" rev-parse HEAD)
REMOTE=$(git -C "$INSTALL_DIR" rev-parse "origin/$BRANCH" 2>/dev/null)

if [[ -z "$REMOTE" ]]; then
    error "Could not resolve remote branch. Check your GitHub remote."
fi

if [[ "$LOCAL" == "$REMOTE" ]]; then
    success "Already up to date — no changes to pull"
    UPDATED=false
else
    info "Changes detected — resetting to origin/$BRANCH…"
    # Use reset --hard so force-pushes and history rewrites are always handled cleanly
    git -C "$INSTALL_DIR" stash --quiet 2>/dev/null || true
    git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
    NEW_VERSION=$(git -C "$INSTALL_DIR" rev-parse --short HEAD)
    success "Updated $CURRENT_VERSION → $NEW_VERSION"

    # Show what changed (best effort — may show nothing after a rebase/rewrite)
    echo ""
    echo -e "${Y}Changes:${N}"
    git -C "$INSTALL_DIR" log --oneline "${LOCAL}..HEAD" 2>/dev/null | head -20 || true
    echo ""
    UPDATED=true
fi

# ── Update dependencies ───────────────────────────────────────────────────────
step "Updating Node.js dependencies"
cd "$INSTALL_DIR"

# Check if package.json changed since last install
PACKAGE_CHANGED=false
if git -C "$INSTALL_DIR" diff --name-only "${LOCAL}" HEAD 2>/dev/null | grep -q "package.json"; then
    PACKAGE_CHANGED=true
fi

if [[ "$PACKAGE_CHANGED" == true ]] || [[ "$UPDATED" == false ]]; then
    npm install --omit=dev --silent
    success "Dependencies up to date"
else
    info "package.json unchanged — skipping npm install"
fi

# ── Reload systemd unit if it changed ────────────────────────────────────────
if git -C "$INSTALL_DIR" diff --name-only "${LOCAL}" HEAD 2>/dev/null | grep -q "stockarena.service"; then
    step "Updating systemd service unit"
    warn "stockarena.service changed — reinstalling unit file"
    sudo cp "$INSTALL_DIR/stockarena.service" /etc/systemd/system/
    sudo systemctl daemon-reload
    success "systemd unit reloaded"
fi

# ── Restart service ───────────────────────────────────────────────────────────
step "Restarting service"
if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    sudo systemctl restart "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "Service restarted successfully"
    else
        error "Service failed to start — check logs: sudo journalctl -u $SERVICE_NAME -n 50"
    fi
else
    warn "systemd service not found — start manually: cd $INSTALL_DIR && npm start"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
NEW_VERSION=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
echo -e "\n${BOLD}${G}╔══════════════════════════════════════════════════════╗${N}"
echo -e "${BOLD}${G}║  ✅  StockArena updated successfully!                ║${N}"
echo -e "${BOLD}${G}╠══════════════════════════════════════════════════════╣${N}"
echo -e "${BOLD}${G}║${N}  Version : ${CURRENT_VERSION} → ${NEW_VERSION}"
echo -e "${BOLD}${G}║${N}  Backup  : ${BACKUP_FILE:-none needed}"
echo -e "${BOLD}${G}╠══════════════════════════════════════════════════════╣${N}"
echo -e "${BOLD}${G}║${N}  Logs    : sudo journalctl -u ${SERVICE_NAME} -f"
echo -e "${BOLD}${G}║${N}  Status  : sudo systemctl status ${SERVICE_NAME}"
echo -e "${BOLD}${G}╚══════════════════════════════════════════════════════╝${N}\n"
