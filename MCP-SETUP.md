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

> Prefer pip? `pipx install localmask`, then add the MCP config shown under
> **Manual config** below (point `command` at your `localmask` env's `python`).

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
