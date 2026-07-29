# LocalMask in your IDE (MCP) — 100% local

LocalMask plugs into your AI chat (Cursor, VS Code / Copilot, Claude Desktop,
Claude Code) as an **MCP server**. It sits between the AI and your code and
**masks every secret and PII value locally** before the AI ever sees it.

- Runs on your machine over stdio — **no network, nothing leaves your computer.**
- The AI only ever sees placeholders like `~[PASSWORD_0]~`, never real values.
- The AI is *told* it's working on masked local code, so it won't guess or leak.

---

## Install (one command)

```bash
curl -sL https://localmaskpro.com/install-mcp.sh | bash
```

This installs LocalMask into `~/.localmask/` and registers the MCP server with
every supported IDE it finds. Restart your IDE afterwards. Done — no account, no
server, no config to edit.

> Prefer pip? `pipx install localmask`, then run **`localmask mcp-install`** —
> it registers the server with every IDE it detects (Cursor, Claude Desktop,
> Claude Code), no JSON editing. Add `--dry-run` to preview, `--project` to also
> drop a `.mcp.json` in the current folder for VS Code / Copilot.

---

## What the AI can do

Once connected, the AI has these local tools (the two you'll use most first):

| Tool | What it does |
|------|--------------|
| **`read_file_masked(path)`** | Read one file with all secrets/PII masked. The AI uses this instead of opening the raw file. |
| **`unmask_text(text)`** | Restore `~[TOKEN]~` placeholders to real values, locally, in code the AI wrote back. |
| `scan_repo(path)` | Whole-repo security overview (what secrets exist, where). |
| `get_detections(scan_id)` | Grouped summary + samples for a scan. |

Just chat normally — *"look at my `config.py` and fix the DB connection"* — and
the AI reads it masked, works on the placeholders, and hands back code you run
locally with the real values intact.

---

## The guarantee, plainly

1. You ask the AI about your code.
2. LocalMask masks secrets **on your machine** → the AI sees `~[TOKEN]~`.
3. The AI answers using those tokens.
4. `unmask_text` restores the real values **on your machine**.

Your secrets never leave your computer, and the AI knows it's only ever shown
masked placeholders.

---

## Manual config (if the installer didn't detect your IDE)

Add this to your IDE's MCP config (Cursor `~/.cursor/mcp.json`, Claude Desktop
`claude_desktop_config.json`, or a project-level `.mcp.json` for VS Code):

```json
{
  "mcpServers": {
    "localmask": {
      "command": "~/.localmask/venv/bin/python3",
      "args": ["~/.localmask/mcp_server.py"]
    }
  }
}
```

No `env` block is needed for local use. (Team/Enterprise only: add
`"env": {"LOCALMASK_SERVER": "https://your-org-server", "LOCALMASK_ORG": "your-org"}`
to sync policy and share the vault across the team.)

---

## The editor extension

### VS Code — from the Marketplace

**Extensions panel → search "LocalMask" → Install** (publisher `localmask`), or:

```bash
code --install-extension localmask.localmask-key-toggle
```

If the LocalMask CLI isn't installed yet, the extension offers a one-click
guided install the first time you click the shield.

### Cursor · Windsurf · VSCodium

The same extension works unchanged in every VS Code fork — search "LocalMask"
in their extension panels (served from OpenVSX), or sideload the VSIX:

```bash
# Cursor
cursor --install-extension localmask-key-toggle-<version>.vsix
# Windsurf
windsurf --install-extension localmask-key-toggle-<version>.vsix
# VSCodium
codium --install-extension localmask-key-toggle-<version>.vsix
```

The MCP side is registered automatically by `localmask mcp-install`
(Cursor uses `~/.cursor/mcp.json`).

### Zed

Zed speaks MCP natively — no extension needed. Add to `~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "localmask": {
      "command": {
        "path": "~/.localmask/venv/bin/python3",
        "args": ["~/.localmask/mcp_server.py"]
      }
    }
  }
}
```

Then ask the assistant: *"Scan this repo for secrets"* — same tools, same
local-only guarantee.

### JetBrains (PyCharm, IntelliJ, DataGrip…)

Native plugin in progress. Meanwhile the CLI covers the whole flow
(`localmask scan / review / decide / publish`), and AI Assistant builds with
MCP support can use the same manual config as above.

---

## Closed / air-gapped environments

LocalMask is built for networks that never touch the internet:

**The guarantee.** Nothing in LocalMask initiates a network connection on its
own. The only two places that can reach out are `localmask check-updates` and
the version line of `localmask license` — both run only when you type them,
and both are blocked by the Closed-Environment network policy unless your
mirror host is explicitly allowlisted. Scanning, masking, review, MCP — all
purely local. Updates are always a human decision.

**Offline install** (no internet at any step):

1. On a connected machine, download once: the edition tarball
   (`localmask-<edition>-<version>.tar.gz`) and the extension
   (`localmask-key-toggle-<version>.vsix`). Move both inside.
2. CLI: unpack the tarball and run `./install-cli.sh` — it installs from the
   local files, no downloads.
3. VS Code: `code --install-extension localmask-key-toggle-<version>.vsix`
   (or Extensions → ⋯ → Install from VSIX). JetBrains: Settings → Plugins →
   ⚙ → Install Plugin from Disk → `localmask-jetbrains-<version>.zip`.

**Recommended org settings:**

- Disable marketplace auto-update and distribute the VSIX from your internal
  artifact store: `"extensions.autoUpdate": false`.
- Point the extension's install button at your mirror:
  `"localmask.installCommand": "sh /opt/mirrors/localmask/install-cli.sh"`.
- Version skew is safe by design: the extension probes `localmask --version`
  and degrades gracefully against an older CLI (core features keep working,
  newer surfaces hide with an update hint) — so you can roll out the CLI and
  the extension on different schedules.
