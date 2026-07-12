"""MCP IDE tools (2026-07-12): read_file_masked + unmask_text give an IDE chat a
one-call, local-only way to read code with secrets masked and to restore tokens.
No real secret value may ever appear in what the tool returns; tokens must be
consistent so a round-trip (mask a file, then unmask) recovers the originals."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LOCALMASK_EDITION", "free")
os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:1")
os.environ.setdefault("LOCALMASK_PERSIST_VAULT", "0")

import localmask.engine as _E  # noqa: E402
_E._get_bert = lambda: None
import mcp_server as m  # noqa: E402

SECRETS = {
    "stripe": "sk_" + "live_" + "51H8xR2eZvKYlo2Cq9Wc3nT7pXbF4mD8",
    "pw": "Pg$ecure#Pr0d_2024",
    "email": "dana.admin@acme.co.il",
}


def _write(tmp):
    p = os.path.join(str(tmp), "config.py")
    with open(p, "w") as f:
        f.write(f'API_KEY = "{SECRETS["stripe"]}"\n'
                f'DB_PASSWORD = "{SECRETS["pw"]}"\n'
                f'ADMIN_EMAIL = "{SECRETS["email"]}"\n')
    return p


def test_read_file_masked_hides_all_real_values(tmp_path):
    # fresh session so token numbering is deterministic within the test
    m._IDE_SESSION = None
    r = json.loads(m.read_file_masked(_write(tmp_path)))
    assert r["masked_count"] == 3
    for real in SECRETS.values():
        assert real not in r["masked_content"], f"leaked {real}"
    assert "~[" in r["masked_content"] and "]~" in r["masked_content"]


def test_unmask_round_trip(tmp_path):
    m._IDE_SESSION = None
    masked = json.loads(m.read_file_masked(_write(tmp_path)))["masked_content"]
    restored = json.loads(m.unmask_text(masked))["text"]
    for real in SECRETS.values():
        assert real in restored, f"unmask lost {real}"


def test_missing_file_is_clean_error(tmp_path):
    m._IDE_SESSION = None
    r = json.loads(m.read_file_masked(os.path.join(str(tmp_path), "nope.py")))
    assert "error" in r


def test_new_tools_are_advertised():
    import asyncio
    names = [t.name for t in asyncio.run(m.mcp.list_tools())]
    assert "read_file_masked" in names
    assert "unmask_text" in names


def test_mcp_install_dry_run_points_at_current_server(capsys):
    # dry-run must not touch any file and must register the mcp_server.py that
    # ships with this CLI (never a possibly-stale ~/.localmask copy).
    import cli
    cli._mcp_install(project=True, dry_run=True)
    out = capsys.readouterr().out
    assert "mcp_server.py" in out
    assert "would write" in out or "would run" in out
    # points at the sibling of cli.py, i.e. the current source
    assert os.path.join(os.path.dirname(os.path.abspath(cli.__file__)),
                        "mcp_server.py") in out


def test_mcp_install_merges_without_clobbering(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    # a pre-existing server must survive the merge
    (home / ".cursor" / "mcp.json").write_text(
        '{"mcpServers":{"other":{"command":"x","args":[]}}}')
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("os.path.expanduser",
                        lambda p: p.replace("~", str(home), 1) if p.startswith("~") else p)
    # avoid the claude CLI subprocess in the test environment
    monkeypatch.setattr("shutil.which", lambda name: None)
    import cli
    cli._mcp_install(project=False, dry_run=False)
    cur = json.loads((home / ".cursor" / "mcp.json").read_text())
    assert "other" in cur["mcpServers"]        # not clobbered
    assert "localmask" in cur["mcpServers"]     # added
