# LocalMask Pro in Docker (private / on-prem / air-gapped)

A single self-contained image: pinned Python, all dependencies, Ollama, and the
Pro edition (AI proxy, LDAP, local model, dashboard). Runs 100% locally — the
only outbound call is the AI provider *you* configure for the proxy.

## Build

```bash
# Standard (models pulled on first run — smaller image, ~2.8GB)
docker build -f Dockerfile.pro -t localmask-pro:0.9.0 .

# Air-gapped (bakes the AI models into the image — ~6GB, no network at runtime)
docker build -f Dockerfile.pro --build-arg BAKE_MODELS=true -t localmask-pro:0.9.0 .
```

## Run

```bash
docker compose -f docker-compose.pro.yml up -d
```

- `http://localhost:8090` — web dashboard + API + MCP
- `http://localhost:8100` — AI proxy (point your AI tools' base_url here)

Volumes persist your license, scans, feedback, and the models across restarts,
so models download only once.

## Activate the license

```bash
docker exec localmask-pro localmask activate LM-PRO-xxxx-xxxx-xxxx
```

## Modes

Set `LOCALMASK_MODE`: `server` (dashboard+API), `proxy` (prompt firewall only),
or `both` (default in compose).

## Strict air-gap

Build with `BAKE_MODELS=true`, or pre-load the `ollama_models` volume and set
`SKIP_MODEL_PULL=1`. The container then makes zero network calls except to the
AI provider you configure for the proxy.
