#!/bin/bash
set -e

# ──────────────────────────────────────────────────────────────
# LocalMask Pro — CLI Installer
#
# Usage:
#   bash install-cli.sh                          # local install (from repo dir)
#   bash install-cli.sh https://server-url       # remote install (download from server)
#   curl -sL https://server-url/cli.py | bash    # one-liner remote install
# ──────────────────────────────────────────────────────────────

SERVER_URL="${1:-}"
INSTALL_DIR="$HOME/.localmask"
BIN_NAME="localmask"

echo ""
echo "================================================"
echo "  LocalMask Pro — CLI Installer"
echo "================================================"
echo ""

# ── Step 1: Create install directory ─────────────────────────
mkdir -p "$INSTALL_DIR"

# ── Step 2: Download CLI ─────────────────────────────────────
echo "[1/3] Downloading CLI..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -n "$SERVER_URL" ]; then
    # Remote install — download from server
    curl -sL "$SERVER_URL/cli.py" -o "$INSTALL_DIR/cli.py"
    echo "  Downloaded from $SERVER_URL"
elif [ -f "$SCRIPT_DIR/cli.py" ]; then
    # Local install — copy from repo directory
    cp "$SCRIPT_DIR/cli.py" "$INSTALL_DIR/cli.py"
    echo "  Copied from local directory"
else
    echo "  Error: cli.py not found."
    echo ""
    echo "  Either run from the LocalMask Pro directory:"
    echo "    bash install-cli.sh"
    echo ""
    echo "  Or provide the server URL:"
    echo "    bash install-cli.sh https://your-server-url"
    exit 1
fi

# ── Step 3: Create wrapper script ────────────────────────────
echo "[2/3] Creating command wrapper..."

WRAPPER="$INSTALL_DIR/$BIN_NAME"
cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/bin/bash
# Use python3 if available, fall back to python
if command -v python3 &>/dev/null; then
    python3 "$HOME/.localmask/cli.py" "$@"
elif command -v python &>/dev/null; then
    python "$HOME/.localmask/cli.py" "$@"
else
    echo "Error: Python not found. Install Python 3 first."
    exit 1
fi
WRAPPER_EOF
chmod +x "$WRAPPER"

# ── Step 4: Add to PATH ─────────────────────────────────────
echo "[3/3] Setting up PATH..."

SHELL_NAME=$(basename "$SHELL")
PROFILE=""
case "$SHELL_NAME" in
    zsh)  PROFILE="$HOME/.zshrc" ;;
    bash) PROFILE="$HOME/.bashrc" ;;
    *)    PROFILE="$HOME/.profile" ;;
esac

PATH_LINE='export PATH="$HOME/.localmask:$PATH"'

if ! grep -qF '.localmask' "$PROFILE" 2>/dev/null; then
    echo "" >> "$PROFILE"
    echo "# LocalMask Pro CLI" >> "$PROFILE"
    echo "$PATH_LINE" >> "$PROFILE"
    echo "  Added to $PROFILE"
else
    echo "  PATH already configured in $PROFILE"
fi

echo ""
echo "================================================"
echo "  INSTALLED!"
echo "================================================"
echo ""
echo "  Restart your terminal or run:"
echo "    source $PROFILE"
echo ""

if [ -n "$SERVER_URL" ]; then
    echo "  Connect to the server:"
    echo "    localmask connect $SERVER_URL"
else
    echo "  Connect to your LocalMask server:"
    echo "    localmask connect https://your-server-url"
fi

echo ""
echo "  Quick start:"
echo "    localmask store-token \"ghp_xxx\""
echo "    localmask set-key anthropic \"sk-ant-xxx\""
echo "    localmask scan https://github.com/org/repo"
echo "    localmask status"
echo "    localmask review <scan_id>"
echo "    localmask approve-all <scan_id>"
echo "    localmask submit <scan_id>"
echo "    localmask publish <scan_id> <target-url>"
echo "    localmask ask <scan_id>"
echo ""
echo "================================================"
