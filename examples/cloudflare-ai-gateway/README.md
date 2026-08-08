# LocalMask + Cloudflare AI Gateway (Pro)

> **Requires LocalMask Pro.** This integration uses server-managed AI routing
> through Cloudflare AI Gateway — the API key stays on your server, never
> travels through the tunnel or Worker.

Two-layer security for AI-powered code review. LocalMask masks your secrets,
AI Gateway catches anything masking might miss.

## Architecture

```
MCP Client → Cloudflare Worker → LocalMask (masks code)
                    │
                    ├→ builds prompt with masked code
                    ├→ AI Gateway (DLP, cache, rate limit, analytics)
                    └→ Anthropic / OpenAI
```

**Layer 1 — LocalMask (masking):** Scans your code, replaces every secret
with `~[TOKEN]~` placeholders. Real values never leave your machine.

**Layer 2 — AI Gateway (safety net):** DLP scans the masked content before
it reaches the AI provider. If masking missed something, DLP blocks the request.
Also provides caching (save API costs), rate limiting, and analytics.

## Security model

| Component | Role | Sees secrets? |
|---|---|---|
| LocalMask (your machine) | Scans & masks all secrets | Yes (source of truth) |
| Cloudflare Worker (edge) | Builds prompt, routes to AI Gateway | No (only `~[TOKEN]~`) |
| AI Gateway (DLP) | Inspects for secrets, blocks if found | No (blocks if it does) |
| AI provider (Anthropic) | Reviews code, gives feedback | No (only `~[TOKEN]~`) |

## Tools

| Tool | Description |
|---|---|
| `scan_repo` | Scan a repo for secrets (via LocalMask) |
| `get_detections` | List detections with types and confidence |
| `get_file_masked` | Read a file with secrets replaced by `~[TOKEN]~` |
| `ask_about_scan` | AI reviews masked code — routed through AI Gateway |
| `test_dlp` | **Demo only**: send unmasked content to verify DLP blocks it |
| `health` | Check LocalMask and AI Gateway connectivity |

## Setup

### 1. Create an AI Gateway

In the [Cloudflare Dashboard](https://dash.cloudflare.com):

1. Go to **AI** → **AI Gateway** → **Create gateway**
2. Name it `localmask`
3. Enable **Collect Logs**, **Cache Responses**, **Rate Limiting**
4. Enable **DLP** with PII detection profiles (API keys, credit cards, etc.)
5. Set DLP action to **Block**
6. Note the gateway URL: `https://gateway.ai.cloudflare.com/v1/{account_id}/localmask`

### 2. Start LocalMask

```bash
cd /path/to/localmask
python3 -m uvicorn server:app --port 8787
```

### 3. Configure the Worker

Edit `wrangler.toml`:

```toml
[vars]
LOCALMASK_API_URL = "http://localhost:8787"  # or your cloudflared tunnel URL
AI_GATEWAY_URL = "https://gateway.ai.cloudflare.com/v1/YOUR_ACCOUNT_ID/localmask"
```

Set secrets:

```bash
npx wrangler secret put ANTHROPIC_API_KEY
npx wrangler secret put AI_GATEWAY_TOKEN     # if authenticated gateway
```

### 4. Run locally

```bash
npm install
npm run dev
```

Worker listens at `http://localhost:8789/mcp`.

### 5. Test the DLP safety net

Connect with any MCP client and call:

- `ask_about_scan` — sends masked code through AI Gateway → **should pass**
- `test_dlp` — sends unmasked fake secrets through AI Gateway → **should be blocked by DLP**

### 6. Deploy

```bash
npm run deploy
```

## How it compares to LocalMask Pro's AI Proxy

LocalMask Pro includes a local AI Proxy (`localmask proxy`) that masks prompts
before forwarding to AI providers. This Worker does the same thing, but at
Cloudflare's edge:

| | LocalMask AI Proxy | This Worker + AI Gateway |
|---|---|---|
| Runs on | Your machine (localhost:8100) | Cloudflare edge |
| Masks via | LocalMask engine (same machine) | LocalMask via tunnel |
| AI routing | Direct to provider | Through AI Gateway |
| DLP safety net | No | Yes (AI Gateway DLP) |
| Caching | No | Yes (AI Gateway cache) |
| Rate limiting | No | Yes (AI Gateway) |
| Analytics | Audit log (local) | AI Gateway dashboard |

## Learn more

- [AI Gateway docs](https://developers.cloudflare.com/ai-gateway/)
- [AI Gateway DLP](https://developers.cloudflare.com/ai-gateway/features/dlp/)
- [LocalMask documentation](https://localmaskpro.com)
