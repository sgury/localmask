"""LocalMask detection & masking engine.

One brain, three mouths: the web server (server.py), the MCP server
(mcp_server.py via server_core.py), and any future CLI all import from here.
"""
import os
import sys

# Top-level helper modules (regex_rules_safe, sensitivity_classifier,
# ner_scanner) live next to this package — make them importable regardless
# of how localmask itself was imported.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
