#!/bin/bash
# LocalMask Pro container entrypoint.
# Starts Ollama, ensures the models exist, then runs the requested service.
#   LOCALMASK_MODE = server (default) | proxy | both
set -e

# If a command is passed (e.g. `docker run img localmask license`), run it
# directly — don't spin up Ollama / the server for one-off inspection commands.
if [ "$#" -gt 0 ]; then exec "$@"; fi

echo "🔒 LocalMask Pro container — edition=$LOCALMASK_EDITION mode=$LOCALMASK_MODE"

# 1. Start Ollama in the background (local AI runtime)
if command -v ollama >/dev/null 2>&1; then
    ollama serve >/tmp/ollama.log 2>&1 &
    for i in $(seq 1 30); do
        curl -sf "$OLLAMA_URL/api/tags" >/dev/null 2>&1 && break
        sleep 1
    done
    # Pull models if missing (skipped automatically when baked in at build time
    # or already present in a mounted volume). Set SKIP_MODEL_PULL=1 for strict
    # air-gapped runs where you've pre-loaded the volume.
    if [ "${SKIP_MODEL_PULL:-0}" != "1" ]; then
        for m in qwen2.5:7b nomic-embed-text; do
            if ! ollama list 2>/dev/null | grep -q "${m%%:*}"; then
                echo "   pulling $m (first run only)…"
                ollama pull "$m" || echo "   ⚠ could not pull $m — proxy/scan still work regex-only"
            fi
        done
    fi
else
    echo "   ⚠ ollama not found — running regex-only (no AI model)"
fi

# 2. Run the requested service(s)
case "$LOCALMASK_MODE" in
    proxy)  exec python -m localmask.proxy ;;
    both)   python -m localmask.proxy & exec python /app/server.py ;;
    *)      exec python /app/server.py ;;
esac
