# LocalMask: Protect Your Code from AI

> Keep secrets and PII out of AI models. LocalMask masks sensitive data before it reaches the LLM — 100% local, nothing leaves your machine. Supports GDPR compliance (Article 25 — Data Protection by Design).

## What it does

LocalMask is a local MCP server that sits between your code and AI models. It automatically detects and masks secrets (API keys, passwords, tokens, connection strings) and PII (emails, names, IPs) before they reach the AI. The AI works with opaque `~[TOKEN_N]~` placeholders — your real values never leave your machine.

## How it works in Cursor

1. **Install** — one click from the marketplace installs LocalMask locally
2. **Scan** — ask Cursor: "scan this repo for secrets" → LocalMask finds them all
3. **Review** — approve or reject each detection in chat
4. **Publish** — push a masked version to a separate git repo (safe to share publicly)
5. **Sync** — git hook keeps masked mirror in sync with every commit
6. **Rehydrate** — when AI returns code with `~[TOKEN_N]~`, LocalMask restores real values locally

## Tiers

| | Free | Pro | Team |
|---|---|---|---|
| Scan & mask | Unlimited | Unlimited | Unlimited |
| Publish masked repo | Yes | Yes | Yes |
| Auto-sync (git hook) | Yes | Yes | Yes |
| Persistent vault (tokens survive restart) | No — cleaned on stop | Yes | Yes (centralized) |
| Finance-grade detection | No | Yes | Yes |
| Security review UI | No | No | Yes |
| User-scoped vault (offboarding) | — | — | Yes |

## 25 MCP Tools

- `scan_repo` — full repo secret scan
- `read_file_masked` — read any file with secrets replaced
- `unmask_text` — restore tokens to real values (local only)
- `mask_prompt` — mask a prompt before sending to AI
- `rehydrate_answer` — restore AI response to real values
- `publish_masked_repo` — push masked version to git
- `sync_repo` — re-sync masked mirror
- `setup_git_hook` — auto-sync on commit
- `review_detection` — approve/reject a finding
- `bulk_review` — batch approve/reject
- And 15 more...

## Privacy & GDPR

- Transport: stdio (local process, no network port)
- Storage: `~/.localmask/vault.sqlite` (encrypted, per-machine key)
- Secrets: NEVER sent to any API, cloud, or network endpoint
- You can verify: the MCP server has zero outbound network calls
- **GDPR-ready**: supports Data Protection by Design (Article 25) and Data Minimization (Article 5) — PII never leaves your machine
- [Data Protection Impact Assessment (DPIA)](https://localmaskpro.com/gdpr)

## Prerequisites

```bash
pip install localmask
```

The plugin's `mcp.json` points to `~/.localmask/mcp_server.py`. If you installed via pip, run `localmask mcp-install` once to set up the MCP server at `~/.localmask/`.

## Plugin structure

```
localmask/
├── .cursor-plugin/
│   └── plugin.json       # Plugin manifest
├── mcp.json              # MCP server (local stdio, zero network)
├── rules/                # Always-on masking rules
├── skills/
│   ├── scan-and-mask/    # Scan repo, review, mask secrets
│   ├── review-and-publish/  # Publish masked mirror to git
│   └── protect-from-ai/    # Guide: protect code from AI + GDPR
├── agents/
│   └── security-scanner.md  # Security-focused scanning agent
├── assets/
│   └── logo.png
└── README.md
```

## Submission

Plugin submitted to Cursor marketplace. Contact: shayguri@gmail.com / kniparko@anysphere.com
