# LocalMask

**Find and mask secrets in your code — 100% locally. Nothing ever leaves your machine.**

LocalMask scans a repository for credentials, keys, tokens, and PII, and replaces
each one with a stable placeholder like `~[DATABASE_PASSWORD_0]~`. You get a masked
copy you can safely paste into an AI tool, share in a ticket, or publish — while
keeping a local map back to the real values.

The free edition is open source and runs entirely offline: a 27+ pattern regex
engine, entropy detection, masking + rehydrate, a publishable masked repo, git
sync, and a CLI + MCP server. No AI model, no cloud, no account.

### New in this version
- **Persistent local vault** — tokens now stay stable across scans, syncs, and
  process restarts (and rehydration works in a fresh process). The mapping is
  stored in an encrypted local SQLite file (`~/.localmask/vault.sqlite`, 0600),
  keyed by repo so re-scanning reuses the same tokens.
- **Editable detection rules (data-driven)** — patterns live in
  `regex_patterns.json`, not hard-coded. Add or tweak rules with no code:
  edit the file, or call `RegexRulesSafe.add_pattern(...)` / `save_patterns()`.

> Want an AI model that catches what patterns miss and learns from your
> corrections, a web dashboard, the [AI proxy](https://localmaskpro.com) that
> scrubs secrets out of your live AI traffic, and a **team-shared vault** so
> everyone gets consistent tokens? See [LocalMask Pro](https://localmaskpro.com).

---

## Install

```bash
pip install localmask          # from PyPI
# or from source:
pip install .
```

Requires Python 3.10+. No ML dependencies.

## Scan a repo

```bash
localmask scan ./my-project
```

You'll see every detected secret, its type, and its placeholder. A masked copy is
kept in the session; publish it or read it back whenever you want.

Sensitivity levels:

```bash
localmask scan ./my-project --sensitivity minimal    # only high-confidence secrets
localmask scan ./my-project --sensitivity standard    # default
localmask scan ./my-project --sensitivity strict      # also flags PII, hostnames, IPs
```

## Edit detections (you're in control)

The engine is a starting point, not the final word. You can correct it — and these
edits are **free**, no model required:

```bash
# Ignore a false positive (stop masking this value)
localmask review            # interactive: mark detections keep / ignore

# Teach it a value the patterns missed (always mask this)
# (done through the review UI or the MCP tools below)
```

Ignoring and teaching update a local lexicon that applies on the next scan/sync.

## Publish a masked copy

```bash
localmask publish <scan_id> --target https://github.com/you/my-project-masked.git
```

Only masked content is pushed. Real values never leave your machine.

## Keep the masked copy in sync

```bash
localmask sync <scan_id>        # re-scan after code changes; tokens stay stable
localmask hook <scan_id>        # install a git hook to auto-sync on commit
```

Unchanged secrets keep the same placeholder across syncs; new secrets get new ones.

## Use it inside your AI editor (MCP)

LocalMask ships an MCP server so assistants (Claude, etc.) can scan and mask on
your behalf. Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "localmask": {
      "command": "python3",
      "args": ["-m", "mcp_server"]
    }
  }
}
```

Then your assistant can call `scan_repo`, `get_detections`, `review_detection`,
`teach_value`, `publish_masked_repo`, and more — all locally.

## How it works

```
your repo ──▶ regex + entropy detection ──▶ mask to ~[TOKEN]~ ──▶ masked copy
                                               │
                                               └── local vault maps tokens ⇄ real values
```

Everything is local. There is no telemetry and no network call in the free edition.

## What's in Free vs Pro

| | Free (this repo) | Pro | Team / Enterprise |
|---|---|---|---|
| Regex + entropy engine, 27+ types | ✓ | ✓ | ✓ |
| Editable pattern rules (`regex_patterns.json`) | ✓ | ✓ | ✓ |
| Mask / rehydrate | ✓ | ✓ | ✓ |
| Persistent local vault (stable tokens, encrypted) | ✓ | ✓ | ✓ |
| Edit detections (ignore / teach) | ✓ | ✓ | ✓ |
| Publish masked repo + git sync | ✓ | ✓ | ✓ |
| CLI + MCP server | ✓ | ✓ | ✓ |
| Local AI model that learns | — | ✓ | ✓ |
| Web dashboard | — | ✓ | ✓ |
| AI proxy (prompt firewall for your AI traffic) | — | ✓ | ✓ |
| Team-shared vault (consistent tokens across machines) | — | — | ✓ |
| Org shared rules · LDAP/AD · SSO | — | — | ✓ |

## License

Free edition released under the MIT license. See `LICENSE`.
