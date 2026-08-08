# Cloudflare Worker Demo — Recording Guide

A ready-to-record demo: scan a fintech repo with hardcoded Stripe keys,
database passwords, and API tokens. LocalMask masks everything before
the AI sees it — through a Cloudflare Worker.

## Quick start (3 terminals)

```bash
# Terminal 1 — LocalMask backend
cd ~/Documents/LocalMask/product
./venv/bin/python3 -m uvicorn server:app --port 8787

# Terminal 2 — Cloudflare Worker
cd ~/Documents/LocalMask/product/examples/cloudflare-agent
npm install
npx wrangler dev --port 8788

# Terminal 3 — the demo (record this one)
cd ~/Documents/LocalMask/product/examples/cloudflare-agent/demo
bash setup-demo-repo.sh        # creates fake fintech repo
npm install --prefix ..         # ensure MCP SDK is available
node run-demo.mjs              # run the demo
```

## Prerequisites

- LocalMask Pro license (for the `ask_about_scan` step)
- An Anthropic API key: `localmask set-key anthropic YOUR_KEY`
- AI backend set to direct: `curl -X POST http://localhost:8787/api/settings -H "Content-Type: application/json" -d '{"ai_backend":"direct"}'`

## What it shows

1. Connect to Worker MCP server (Streamable HTTP)
2. Scan a payment repo — finds 10 secrets (Stripe keys, DB passwords, SendGrid, JWT, etc.)
3. Read masked payment code — `stripe.api_key = "~[STRIPE_SECRET_KEY_0]~"`
4. Read masked .env — every value replaced with `~[TOKEN]~`
5. Side-by-side comparison: leaked vs. masked
6. **AI reviews the masked code** — gives real security feedback without ever seeing a real key

## Recording tips

- Use a dark terminal theme for contrast
- Font size 16+ for readability
- The demo runs in ~5 seconds, so pause after each step if narrating
- Tools: QuickTime (screen record), OBS, or asciinema for terminal-only
