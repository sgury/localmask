# LocalMask + Cloudflare Worker

A Cloudflare Worker that exposes LocalMask's PII masking tools as a **remote MCP server**
over Streamable HTTP. Any MCP client can connect to it — no local install required on
the client side.

## Architecture

```
MCP Client ──→ Worker (Cloudflare Edge) ──→ cloudflared tunnel ──→ LocalMask HTTP API
                Streamable HTTP                                     (your machine)
```

Secrets never reach the edge. All masking happens on your machine; only masked content
(with `~[TOKEN]~` placeholders) crosses the wire.

## Tools exposed

| Tool | Description |
|------|-------------|
| `scan_repo` | Scan a repo for secrets/PII, get a `scan_id` |
| `get_detections` | List detections with types, confidence, review status |
| `get_file_masked` | Read a file with secrets replaced by `~[TOKEN]~` |
| `review_detection` | Approve or reject detections |
| `publish_masked_repo` | Push the masked copy to a git remote |
| `ask_about_scan` | Ask AI to analyze the scanned repo (Pro) |
| `health` | Check backend connectivity |

## Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Python 3.10+](https://python.org/) with LocalMask installed (`pip install localmask`)
- [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) installed
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)

## Setup

### 1. Start LocalMask HTTP API

```bash
cd /path/to/localmask
python3 -m uvicorn server:app --port 8787
```

### 2. Start a cloudflared tunnel

```bash
cloudflared tunnel --url http://localhost:8787
```

Copy the tunnel URL (e.g. `https://random-words.trycloudflare.com`).

### 3. Configure the Worker

Edit `wrangler.toml` and set your tunnel URL:

```toml
[vars]
LOCALMASK_API_URL = "https://random-words.trycloudflare.com"
```

Optionally set an API key (if your LocalMask instance requires auth):

```bash
npx wrangler secret put LOCALMASK_API_KEY
```

### 4. Run locally

```bash
npm install
npm run dev
```

The Worker is now listening at `http://localhost:8788/mcp`.

### 5. Test with an MCP client

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const transport = new StreamableHTTPClientTransport(
  new URL("http://localhost:8788/mcp")
);
const client = new Client({ name: "test", version: "1.0.0" });
await client.connect(transport);

const { tools } = await client.listTools();
console.log(tools.map(t => t.name));
// → ["scan_repo", "get_detections", "get_file_masked", "review_detection", "publish_masked_repo", "health"]

// For large repos, increase the timeout on scan_repo (default is 60s):
const result = await client.callTool(
  { name: "scan_repo", arguments: { source: "/path/to/large-repo" } },
  undefined,
  { timeout: 300_000 }  // 5 minutes
);
```

> **Large repos**: `scan_repo` blocks until the scan completes. For large
> repositories this can take a few minutes. Set a longer client-side timeout
> (see above) or the MCP SDK's default 60s timeout will cancel the request.

### 6. Deploy to Cloudflare

```bash
npm run deploy
```

Your remote MCP server is now live at `https://localmask-agent.<your-subdomain>.workers.dev/mcp`.

## Security model

### What each layer sees

| Component | Sees real secrets? | Details |
|---|---|---|
| LocalMask (your machine) | **Yes** | Scans original files, stores masked + real mappings locally |
| Cloudflare Worker (edge) | **No** | Only receives masked content (`~[TOKEN]~` placeholders) |
| cloudflared tunnel (wire) | **No** | HTTPS-encrypted, only masked content crosses the wire |
| Team members (MCP clients) | **No** | Only receive masked content from the Worker |
| AI provider (Anthropic, etc.) | **No** | `ask_about_scan` sends only masked code to the AI |

### Path traversal protection

By default, `scan_repo` **blocks local file paths** (e.g. `/etc/passwd`, `~/.ssh/`).
Only git URLs (`https://`, `git@`) are allowed. This prevents remote users from
reading arbitrary files on your server.

For local development, set `ALLOW_LOCAL_PATHS = "true"` in `wrangler.toml`.
**Remove this before deploying to production.**

### AI API keys

The `ask_about_scan` tool uses the API key stored on the LocalMask server
(set via `localmask set-key anthropic YOUR_KEY`). The key **never leaves
your machine** — LocalMask calls the AI provider directly from the server.
Team members do not send or see the key. The server owner pays for AI calls.

### Recommendations

- **Tunnel protection**: The free `trycloudflare.com` tunnel URL is publicly accessible.
  For production, use a [named tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
  with access policies.
- **API key**: Set `LOCALMASK_API_KEY` as a Worker secret and configure your LocalMask
  instance to require it (`LOCALMASK_API_KEY` env var on the server side).
- **No secrets on the edge**: The Worker only sees masked content. Real secret values
  stay on your machine behind the tunnel.
- **ALLOW_LOCAL_PATHS**: Always set to `"false"` (or remove) in production deployments.

## Learn more

- [LocalMask documentation](https://localmaskpro.com)
- [Cloudflare Agents SDK — MCP](https://developers.cloudflare.com/agents/model-context-protocol/)
- [MCP specification](https://modelcontextprotocol.io/)
