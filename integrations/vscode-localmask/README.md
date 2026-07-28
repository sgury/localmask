# LocalMask — mask secrets before any AI sees your code

100% local. LocalMask scans your repo for secrets & PII, replaces them with
opaque tokens (`~[PASSWORD_0]~`), and keeps the real values on your machine.
Your AI assistant — Copilot, Cursor, Claude, anything — only ever sees the
masked view.

Requires the LocalMask CLI (free): `curl -sL https://localmaskpro.com/install-mcp.sh | bash`

## Always on

- **🛡 Shield** (status bar) — scan/sync, approve all, publish the masked
  mirror, review, teach, install the commit hook. Shows where you are:
  `14 findings · ⏳ 3 to review`.
- **🔑 Key toggle** (`Cmd+Alt+K`) — flip any file between real values and the
  masked view (what the AI sees). Reflects review decisions instantly.

## Opt-in (Settings → LocalMask — each surface has its own switch)

- **Problems panel + quick fixes** — pending detections as warnings; lightbulb
  → *Approve masking* / *Reject — false positive* (your reason teaches the
  local model).
- **Inline highlights** — detected lines tinted by state: pending / 🛡 masked /
  ○ kept readable.
- **Review sidebar** — every finding with its actual value (your screen only),
  click to jump to it, ✓/✗ inline, whole-file decisions (file-scoped: rejected
  values stay masked elsewhere in the repo).
- **Right-click 🛡 menu** — *Mark selection as secret* (value passes over
  stdin — never argv, never any AI), approve/reject on line, compare.
- **⇄ Compare** — real vs masked side by side.
- **Sync on save** — masked store follows your edits automatically.
- **Teach types** — add your own token categories (e.g. `CUSTOMER_ID`).

## Works in

VS Code, **Cursor**, **Windsurf**, **VSCodium** (same extension). The AI-chat
side works in every MCP-capable client — Claude Code, Claude Desktop, Copilot,
Zed — via `localmask mcp-install`.

## Privacy model

Everything runs on your machine over stdio. No accounts, no network calls,
no telemetry. The AI sees tokens; you keep the values.
