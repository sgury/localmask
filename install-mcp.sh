#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# LocalMask Pro — MCP Server Installer
#
# Installs LocalMask Pro as a local MCP service for VS Code
# and Claude Desktop. Everything runs on your machine.
#
# Usage:
#   curl -sL <your-url>/install-mcp.sh | bash
#   — or —
#   bash install-mcp.sh
# ═══════════════════════════════════════════════════════════════

set -e

GREEN="\033[92m"
RED="\033[91m"
CYAN="\033[96m"
YELLOW="\033[93m"
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

INSTALL_DIR="$HOME/.localmask"
VENV_DIR="$INSTALL_DIR/venv"
MCP_SERVER="$INSTALL_DIR/mcp_server.py"

echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║                                               ║${RESET}"
echo -e "${BOLD}${CYAN}║   🔐 LocalMask Pro — MCP Server Installer     ║${RESET}"
echo -e "${BOLD}${CYAN}║                                               ║${RESET}"
echo -e "${BOLD}${CYAN}║   100% local — secrets never leave your PC    ║${RESET}"
echo -e "${BOLD}${CYAN}║                                               ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Step 1: Check prerequisites ─────────────────────────────────

echo -e "${BOLD}[1/6] Checking prerequisites...${RESET}"

# Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found. Install from https://python.org${RESET}"
    exit 1
fi
PY_VER=$(python3 --version 2>&1)
echo -e "  ${GREEN}✓${RESET} $PY_VER"

# Git
if ! command -v git &> /dev/null; then
    echo -e "${RED}✗ Git not found. Install from https://git-scm.com${RESET}"
    exit 1
fi
echo -e "  ${GREEN}✓${RESET} git $(git --version | cut -d' ' -f3)"

# Ollama
if ! command -v ollama &> /dev/null; then
    echo -e "${YELLOW}⚠ Ollama not found. Installing...${RESET}"
    echo -e "  ${DIM}Visit https://ollama.ai to install manually if this fails${RESET}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install ollama 2>/dev/null || {
            echo -e "${RED}  ✗ Auto-install failed. Please install Ollama manually:${RESET}"
            echo -e "  ${CYAN}https://ollama.ai/download${RESET}"
            exit 1
        }
    else
        curl -fsSL https://ollama.ai/install.sh | sh
    fi
fi
echo -e "  ${GREEN}✓${RESET} ollama installed"

# ── Step 2: Ensure Ollama is running ────────────────────────────

echo -e "\n${BOLD}[2/6] Starting Ollama service...${RESET}"

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "  ${DIM}Starting Ollama...${RESET}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: Ollama runs as a menu bar app
        open -a Ollama 2>/dev/null || ollama serve &
    else
        ollama serve &
    fi
    sleep 3
    if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${RED}  ✗ Could not start Ollama. Start it manually and re-run.${RESET}"
        exit 1
    fi
fi
echo -e "  ${GREEN}✓${RESET} Ollama running"

# ── Step 3: Pull detection model ────────────────────────────────

echo -e "\n${BOLD}[3/6] Pulling detection model (qwen2.5:7b)...${RESET}"

MODELS=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys,json; print(' '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null)

if echo "$MODELS" | grep -q "qwen2.5:7b"; then
    echo -e "  ${GREEN}✓${RESET} qwen2.5:7b already available"
else
    echo -e "  ${DIM}Downloading qwen2.5:7b (~4.7 GB)... this may take a few minutes${RESET}"
    ollama pull qwen2.5:7b
    echo -e "  ${GREEN}✓${RESET} Model ready"
fi

# ── Step 4: Install LocalMask Pro ───────────────────────────────

echo -e "\n${BOLD}[4/6] Installing LocalMask Pro...${RESET}"

mkdir -p "$INSTALL_DIR"

# Copy all necessary files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_FILES=(
    mcp_server.py server_core.py server.py licensing.py
    sensitivity_classifier.py ner_scanner.py regex_rules_safe.py
    safe_scanner.py context_classifier.py org_rules.py
    document_subject_classifier.py detector_pipeline.py
    cli.py feedback_data.jsonl
)

for f in "${CORE_FILES[@]}"; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        cp "$SCRIPT_DIR/$f" "$INSTALL_DIR/$f"
    fi
done

# Create __init__.py
touch "$INSTALL_DIR/__init__.py"

echo -e "  ${GREEN}✓${RESET} Files copied to $INSTALL_DIR"

# Create venv and install deps
if [ ! -d "$VENV_DIR" ]; then
    echo -e "  ${DIM}Creating virtual environment...${RESET}"
    python3 -m venv "$VENV_DIR"
fi

echo -e "  ${DIM}Installing Python dependencies...${RESET}"
"$VENV_DIR/bin/pip" install -q \
    "fastapi>=0.104.0" "uvicorn>=0.24.0" "mcp>=1.28.0" \
    "requests>=2.31.0" "pydantic>=2.4.0" "pyyaml>=6.0.1" \
    "anthropic>=0.25.0" "openai>=1.12.0" 2>&1 | tail -1

# Optional heavy deps (spacy, transformers) — skip if not needed
echo -e "  ${DIM}(Skipping optional ML deps — spacy/torch for lighter install)${RESET}"

echo -e "  ${GREEN}✓${RESET} Dependencies installed"

# ── Install the localmask package into the venv ─────────────────
# server_core/cli import `localmask.*`; the package dir (engine, masking,
# pattern DBs) must live in site-packages. Remove any stale pip-installed
# copy first so it can't shadow this release.
if [ -d "$SCRIPT_DIR/localmask" ]; then
    SITE_PKGS=$("$VENV_DIR/bin/python3" -c "import site; print(site.getsitepackages()[0])")
    rm -rf "$SITE_PKGS/localmask"
    cp -R "$SCRIPT_DIR/localmask" "$SITE_PKGS/localmask"
    # Pattern DBs also load from the install dir (regex_rules_safe fallback)
    cp "$SCRIPT_DIR/localmask/regex_patterns.json" "$INSTALL_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/localmask/ner_patterns.json" "$INSTALL_DIR/" 2>/dev/null || true
    echo -e "  ${GREEN}✓${RESET} localmask engine package installed"
fi

# ── Step 5: Configure MCP ───────────────────────────────────────

echo -e "\n${BOLD}[5/7] Configuring MCP for all IDEs...${RESET}"

MCP_PYTHON="$VENV_DIR/bin/python3"
MCP_SCRIPT="$INSTALL_DIR/mcp_server.py"

MCP_CONFIG='{
    "command": "'"$MCP_PYTHON"'",
    "args": ["'"$MCP_SCRIPT"'"]
}'

# ── Claude Desktop ──────────────────────────────────────────────
CLAUDE_CONFIG_DIR="$HOME/Library/Application Support/Claude"
if [ -d "$CLAUDE_CONFIG_DIR" ]; then
    CLAUDE_CONFIG="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"
    if [ -f "$CLAUDE_CONFIG" ]; then
        python3 -c "
import json
with open('$CLAUDE_CONFIG') as f:
    cfg = json.load(f)
cfg.setdefault('mcpServers', {})['localmask'] = {
    'command': '$MCP_PYTHON',
    'args': ['$MCP_SCRIPT']
}
with open('$CLAUDE_CONFIG', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null
        echo -e "  ${GREEN}✓${RESET} Claude Desktop — updated config"
    else
        cat > "$CLAUDE_CONFIG" << CEOF
{
  "mcpServers": {
    "localmask": {
      "command": "$MCP_PYTHON",
      "args": ["$MCP_SCRIPT"]
    }
  }
}
CEOF
        echo -e "  ${GREEN}✓${RESET} Claude Desktop — created config"
    fi
else
    echo -e "  ${DIM}  Claude Desktop not found — skipping${RESET}"
fi

# ── Claude Code (CLI) ──────────────────────────────────────────
if command -v claude &>/dev/null; then
    claude mcp add localmask "$MCP_PYTHON" "$MCP_SCRIPT" 2>/dev/null \
        && echo -e "  ${GREEN}✓${RESET} Claude Code (CLI) — registered MCP server" \
        || echo -e "  ${DIM}  Claude Code — manual setup needed (see below)${RESET}"
else
    echo -e "  ${DIM}  Claude Code CLI not found — install from https://claude.ai/code${RESET}"
fi

# ── Cursor ──────────────────────────────────────────────────────
CURSOR_CONFIG_DIR="$HOME/.cursor"
if [ -d "$CURSOR_CONFIG_DIR" ] || command -v cursor &>/dev/null; then
    mkdir -p "$CURSOR_CONFIG_DIR"
    CURSOR_MCP="$CURSOR_CONFIG_DIR/mcp.json"
    if [ -f "$CURSOR_MCP" ]; then
        python3 -c "
import json
with open('$CURSOR_MCP') as f:
    cfg = json.load(f)
cfg.setdefault('mcpServers', {})['localmask'] = {
    'command': '$MCP_PYTHON',
    'args': ['$MCP_SCRIPT']
}
with open('$CURSOR_MCP', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null
        echo -e "  ${GREEN}✓${RESET} Cursor — updated ~/.cursor/mcp.json"
    else
        cat > "$CURSOR_MCP" << CUEOF
{
  "mcpServers": {
    "localmask": {
      "command": "$MCP_PYTHON",
      "args": ["$MCP_SCRIPT"]
    }
  }
}
CUEOF
        echo -e "  ${GREEN}✓${RESET} Cursor — created ~/.cursor/mcp.json"
    fi
else
    echo -e "  ${DIM}  Cursor not found — skipping${RESET}"
fi

# ── VS Code / Copilot (project-level .mcp.json) ────────────────
cat > "$INSTALL_DIR/.mcp.json" << MEOF
{
  "mcpServers": {
    "localmask": {
      "command": "$MCP_PYTHON",
      "args": ["$MCP_SCRIPT"]
    }
  }
}
MEOF
echo -e "  ${GREEN}✓${RESET} VS Code — created .mcp.json template"
echo -e "  ${DIM}  Copy to any project: cp ~/.localmask/.mcp.json ./your-project/${RESET}"

# ── Windsurf ────────────────────────────────────────────────────
WINDSURF_DIR="$HOME/.codeium/windsurf"
if [ -d "$WINDSURF_DIR" ]; then
    WINDSURF_MCP="$WINDSURF_DIR/mcp_config.json"
    python3 -c "
import json, os
path = '$WINDSURF_MCP'
cfg = {}
if os.path.exists(path):
    with open(path) as f: cfg = json.load(f)
cfg.setdefault('mcpServers', {})['localmask'] = {
    'command': '$MCP_PYTHON',
    'args': ['$MCP_SCRIPT']
}
with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null
    echo -e "  ${GREEN}✓${RESET} Windsurf — updated mcp_config.json"
else
    echo -e "  ${DIM}  Windsurf not found — skipping${RESET}"
fi

# ── Step 6: Org server connection (optional) ───────────────────

echo -e "\n${BOLD}[6/7] Org server connection...${RESET}"

if [ -n "$LOCALMASK_SERVER" ]; then
    echo -e "  ${GREEN}✓${RESET} Org server: $LOCALMASK_SERVER"

    # Update MCP configs to include org server env vars
    MCP_ENV_BLOCK='"env": {"LOCALMASK_SERVER": "'"$LOCALMASK_SERVER"'", "LOCALMASK_ORG": "'"${LOCALMASK_ORG:-my-org}"'"}'

    # Update Claude Desktop config
    if [ -f "$CLAUDE_CONFIG" ]; then
        python3 -c "
import json
with open('$CLAUDE_CONFIG') as f:
    cfg = json.load(f)
lm = cfg.get('mcpServers', {}).get('localmask', {})
lm['env'] = {'LOCALMASK_SERVER': '$LOCALMASK_SERVER', 'LOCALMASK_ORG': '${LOCALMASK_ORG:-my-org}'}
cfg['mcpServers']['localmask'] = lm
with open('$CLAUDE_CONFIG', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null
        echo -e "  ${GREEN}✓${RESET} Updated Claude Desktop config with org server"
    fi

    # Update .mcp.json template
    cat > "$INSTALL_DIR/.mcp.json" << OEOF
{
  "mcpServers": {
    "localmask": {
      "command": "$MCP_PYTHON",
      "args": ["$MCP_SCRIPT"],
      "env": {
        "LOCALMASK_SERVER": "$LOCALMASK_SERVER",
        "LOCALMASK_ORG": "${LOCALMASK_ORG:-my-org}"
      }
    }
  }
}
OEOF
    echo -e "  ${GREEN}✓${RESET} Updated .mcp.json with org server"

    # Activate license if provided
    if [ -n "$LOCALMASK_KEY" ]; then
        "$VENV_DIR/bin/python3" "$INSTALL_DIR/cli.py" activate "$LOCALMASK_KEY" --server "$LOCALMASK_SERVER" 2>/dev/null \
            && echo -e "  ${GREEN}✓${RESET} License activated" \
            || echo -e "  ${YELLOW}⚠ License activation pending — run: localmask activate <YOUR-KEY>${RESET}"
    else
        echo -e "  ${DIM}  Run: localmask activate <YOUR-KEY> to activate license${RESET}"
    fi
else
    echo -e "  ${DIM}No org server configured (standalone mode)${RESET}"
    echo -e "  ${DIM}Set LOCALMASK_SERVER=http://your-server:8090 to connect${RESET}"
fi

# ── Step 7: Create CLI shortcut ─────────────────────────────────

echo -e "\n${BOLD}[7/7] Creating CLI shortcut...${RESET}"

cat > "$INSTALL_DIR/localmask" << 'SEOF'
#!/bin/bash
INSTALL_DIR="$HOME/.localmask"
"$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/cli.py" "$@"
SEOF
chmod +x "$INSTALL_DIR/localmask"

# Add to PATH if not already there
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    SHELL_RC="$HOME/.zshrc"
    [ -f "$HOME/.bashrc" ] && SHELL_RC="$HOME/.bashrc"
    if ! grep -q "localmask" "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH="$HOME/.localmask:$PATH"' >> "$SHELL_RC"
        echo -e "  ${GREEN}✓${RESET} Added to PATH in $SHELL_RC"
        echo -e "  ${DIM}Run: source $SHELL_RC  (or restart terminal)${RESET}"
    fi
fi

echo -e "  ${GREEN}✓${RESET} CLI available as: localmask"

# ── Done ────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║                                               ║${RESET}"
echo -e "${BOLD}${GREEN}║   ✅ LocalMask Pro installed!                  ║${RESET}"
echo -e "${BOLD}${GREEN}║                                               ║${RESET}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}What's running:${RESET}"
echo -e "    ${GREEN}✓${RESET} Ollama (local AI model)     — http://localhost:11434"
echo -e "    ${GREEN}✓${RESET} MCP Server (stdio)          — auto-started by your IDE"
echo ""
echo -e "  ${BOLD}Supported IDEs (auto-configured):${RESET}"
echo -e "    ${GREEN}✓${RESET} Claude Desktop      ${DIM}— restart app${RESET}"
echo -e "    ${GREEN}✓${RESET} Claude Code (CLI)   ${DIM}— works immediately${RESET}"
echo -e "    ${GREEN}✓${RESET} VS Code / Copilot   ${DIM}— copy .mcp.json to project${RESET}"
echo -e "    ${GREEN}✓${RESET} Cursor              ${DIM}— restart app${RESET}"
echo -e "    ${GREEN}✓${RESET} Windsurf            ${DIM}— restart app${RESET}"
echo ""
echo -e "  ${BOLD}AI Providers for ask command:${RESET}"
echo -e "    localmask set-key anthropic sk-ant-...   ${DIM}# Claude${RESET}"
echo -e "    localmask set-key openai sk-...          ${DIM}# GPT-4o${RESET}"
echo -e "    localmask set-key gemini AIza...         ${DIM}# Gemini${RESET}"
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo -e "    ${CYAN}1.${RESET} Restart your IDE"
echo -e "    ${CYAN}2.${RESET} Ask AI: ${DIM}\"Scan https://github.com/org/repo for secrets\"${RESET}"
echo ""
echo -e "  ${BOLD}CLI commands:${RESET}"
echo -e "    localmask scan <repo-url>       ${DIM}# scan a repo${RESET}"
echo -e "    localmask sync <scan_id>        ${DIM}# re-scan after git updates${RESET}"
echo -e "    localmask hook <scan_id>        ${DIM}# auto-sync on every commit${RESET}"
echo -e "    localmask license               ${DIM}# check tier${RESET}"
echo -e "    localmask activate LM-PRO-...   ${DIM}# activate Pro license${RESET}"
echo ""
echo -e "  ${BOLD}For VS Code projects:${RESET}"
echo -e "    cp $INSTALL_DIR/.mcp.json ./    ${DIM}# add to any project${RESET}"
echo ""
