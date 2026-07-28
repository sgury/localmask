# Downloading LocalMask

## Free edition (open source)

Three ways, pick one:

```bash
# 1. From PyPI (once published)
pip install localmask

# 2. From source
git clone https://github.com/sgury11/localmask
pip install ./localmask

# 3. From a release tarball
tar -xzf localmask-free-0.9.0.tar.gz && cd localmask-free-0.9.0 && pip install .
```

Requires Python 3.10+. No ML or cloud dependencies.

### Quickstart

```bash
localmask scan ./your-repo                       # find + mask secrets locally
localmask publish <scan_id> <masked-repo-url>    # push a private masked git mirror
localmask sync <scan_id>                          # keep the mirror current on changes
```

Point your AI tools / agents at the **masked mirror**, not your real repo — they
get working code with every secret replaced by a stable `~[TOKEN]~`.

MCP (inside AI editors): add to `.mcp.json`:

```json
{ "mcpServers": { "localmask": { "command": "python3", "args": ["-m", "mcp_server"] } } }
```

## Pro edition

Pro is delivered after purchase (see pricing at https://localmaskpro.com). You'll
get a download link and an annual license key:

```bash
tar -xzf localmask-pro-0.9.0.tar.gz && cd localmask-pro-0.9.0
bash install-mcp.sh
localmask activate LM-PRO-xxxx-xxxx-xxxx      # 1-year key, validated offline
localmask proxy --port 8100                    # start the AI proxy (Pro)
```

Pro also needs a local [Ollama](https://ollama.com):

```bash
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
```
