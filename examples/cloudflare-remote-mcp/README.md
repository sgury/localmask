# LocalMask Remote MCP Server on Cloudflare Workers

A production-ready remote MCP server that exposes the **full LocalMask tool surface**
over Streamable HTTP. Any MCP client can connect — no local LocalMask install required.

## Architecture

```
                        Cloudflare Edge                          Your Infrastructure
┌───────────┐      ┌───────────────────────┐      ┌──────────────────────────────────┐
│ MCP Client│─────▶│  Worker (this code)   │─────▶│  LocalMask HTTP API (server.py)  │
│ (any SDK) │◀─────│  Streamable HTTP      │◀─────│  Cloud Run / Fly.io / Railway    │
│           │      │  + Bearer auth        │      │  or cloudflared tunnel           │
└───────────┘      └───────────────────────┘      └──────────────────────────────────┘
                    MCP protocol (JSON-RPC)         REST API (JSON)
```

Secrets never reach the edge. All detection and masking happens on the backend —
the Worker only sees and forwards masked content with `~[TOKEN]~` placeholders.

## Tools (15)

| Category | Tools |
|----------|-------|
| **Scanning** | `scan_repo`, `sync_repo`, `list_scans` |
| **Detections** | `get_detections`, `get_review_queue` |
| **Review** | `review_detection`, `bulk_review` |
| **Files** | `get_file_masked` |
| **Workflow** | `submit_for_review`, `approve_scan` |
| **Publishing** | `publish_masked_repo` |
| **AI Analysis** | `ask_about_scan` |
| **Model** | `get_model_stats`, `retrain_model` |
| **Utility** | `health` |

## Prerequisites

- Node.js 18+
- A Cloudflare account
- A running LocalMask HTTP API backend (see [Backend options](#backend-options) below)

## Quick start

```bash
# Clone and install
cd examples/cloudflare-remote-mcp
npm install

# Set your backend URL
# Edit wrangler.toml → LOCALMASK_API_URL

# Set secrets
npx wrangler secret put LOCALMASK_API_KEY    # backend API key
npx wrangler secret put MCP_AUTH_TOKEN       # token clients use to auth with this Worker

# Deploy
npx wrangler deploy
```

Your remote MCP server is live at:
```
https://localmask-remote-mcp.<your-subdomain>.workers.dev/mcp
```

## Connecting an MCP client

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const transport = new StreamableHTTPClientTransport(
  new URL("https://localmask-remote-mcp.your-subdomain.workers.dev/mcp"),
  { requestInit: { headers: { Authorization: "Bearer YOUR_MCP_AUTH_TOKEN" } } }
);

const client = new Client({ name: "my-app", version: "1.0.0" });
await client.connect(transport);

// Scan a repo (use a longer timeout for large repos — scan is synchronous)
const scan = await client.callTool(
  { name: "scan_repo", arguments: { source: "https://github.com/org/repo", sensitivity: "standard" } },
  undefined,
  { timeout: 300_000 },  // 5 minutes
);

// Read a file with secrets masked
const file = await client.callTool({
  name: "get_file_masked",
  arguments: { scan_id: "scan_abc123", path: "src/config.py" },
});
// → { masked_content: "DB_PASS = ~[PASSWORD_0]~", ... }
```

## Backend options

The Worker proxies all tool calls to a LocalMask HTTP API. Options for hosting:

### Option 1: cloudflared tunnel (development)

```bash
# On your machine:
pip install localmask
cd /path/to/localmask
python3 -m uvicorn server:app --port 8787

# In another terminal:
cloudflared tunnel --url http://localhost:8787
# → https://random-words.trycloudflare.com
```

Set `LOCALMASK_API_URL` to the tunnel URL. Free, instant, but not persistent.

### Option 2: Google Cloud Run (production)

```bash
# From the localmask product directory:
gcloud run deploy localmask-api \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars LOCALMASK_API_KEY=your-secret-key
```

### Option 3: Fly.io

```bash
fly launch --name localmask-api
fly secrets set LOCALMASK_API_KEY=your-secret-key
fly deploy
```

### Option 4: Docker (any host)

```bash
docker build -t localmask-api .
docker run -p 8787:8787 -e LOCALMASK_API_KEY=your-secret-key localmask-api
```

## Security

- **MCP_AUTH_TOKEN**: Bearer token that MCP clients must include. Set via
  `wrangler secret put`. Without it, the endpoint is open.
- **LOCALMASK_API_KEY**: Token the Worker uses to authenticate with the
  LocalMask backend. Set via `wrangler secret put`.
- **No secrets on the edge**: The Worker never sees real secret values —
  only `~[TOKEN]~` placeholders cross the wire.
- **HTTPS only**: Both the Worker endpoint and backend connection use TLS.

## Local development

```bash
# Start LocalMask backend
cd /path/to/localmask
python3 -m uvicorn server:app --port 8787

# Start Worker (override API URL for local testing)
cd examples/cloudflare-remote-mcp
npm install
# Edit wrangler.toml: LOCALMASK_API_URL = "http://localhost:8787"
npx wrangler dev
```

## Differences from `cloudflare-agent/` example

| | `cloudflare-agent/` | `cloudflare-remote-mcp/` (this) |
|---|---|---|
| Tools | 6 (core subset) | 15 (full surface) |
| Auth | None | Bearer token |
| Purpose | Quick demo / PoC | Production deployment |
| Backend | cloudflared tunnel | Any hosted instance |

## Learn more

- [LocalMask](https://localmaskpro.com)
- [Cloudflare Agents SDK — Remote MCP](https://developers.cloudflare.com/agents/model-context-protocol/guides/remote-mcp-server/)
- [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http)
