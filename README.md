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

# Teach a secret the patterns MISSED (always mask this value)
localmask teach <scan_id> "the-exact-missed-value" --subtype API_KEY
localmask teach <scan_id> "a-false-positive" --allow      # or: never mask it

# …or do it inside the review UI: press [T] to teach a missed value,
# and it re-scans in place so you see it masked immediately.
```

Ignoring and teaching update a **persistent local lexicon** (stored encrypted
next to the vault, keyed by repo), so they apply automatically on **every future
scan and sync** of that repo — even in a fresh process. On a Team/Enterprise
shared vault, taught values propagate to the whole team.

## Publish a masked copy

```bash
localmask publish <scan_id> https://github.com/you/my-project-masked.git
```

Only masked content is pushed. Real values never leave your machine.

### Approval gate (review before publishing)

By default LocalMask **won't publish until the scan is reviewed & approved** — so
a masked mirror never goes out (and `sync`/`hook` never auto-republish) with
unreviewed detections. Approve either way:

```bash
localmask review <scan_id>        # decide each detection; approves when none are left pending
localmask approve-all <scan_id>   # approve everything in one step
localmask publish <scan_id> <url> # now allowed
```

New secrets found on a later `sync` **un-approve** the scan and hold the mirror
until you review them again. Prefer no gate (auto-approve + auto-publish on every
change)? Switch the policy:

```bash
localmask config                        # show current settings
localmask config publish-policy auto    # auto-approve + auto-republish
localmask config publish-policy review  # back to manual gate (default)
localmask publish <scan> <url> --force  # one-off override of the gate
```

## Let your AI read the masked code (two ways)

The masked copy has only `~[TOKEN]~` placeholders — no real secrets — so the AI
can read it safely. **LocalMask never hands the AI any git credentials.** Pick
whichever fits:

**A) The AI reads the published masked git mirror.** Keep the masked repo private
and give the AI *its own* read access — a read-only collaborator, a read-only
deploy key, or a GitHub/GitLab App. The AI **clones/pulls that repo** (a copy on
its side, separate from your real code) and authenticates as itself; LocalMask
never shares your git token. **To get the updated version after you change code:**
`localmask sync <scan>` re-masks and re-pushes the mirror (once approved), and the
AI runs `git pull`. (Because it's masked you *could* also make the mirror public
and skip auth — no secrets are in it.)

**B) The AI reads live from LocalMask — nothing published.** In your AI editor's
MCP config, the assistant calls the `get_detections` and `get_file_masked` tools.
No git repo, no push, no `git pull` — LocalMask serves the **current** masked
content on each call (run `localmask sync <scan>` after code changes so the next
read is fresh). Use this when you don't want a mirror at all.

**Which to use:** (A) the AI holds its own git copy and *pulls* to update — good
for agents/CI that clone a repo; (B) LocalMask streams the masked files live,
always current, no repo. Either way the AI only ever sees `~[TOKEN]~` placeholders
and signs in with its own identity — LocalMask stays out of its authentication.

## Keep the masked copy in sync

```bash
localmask sync <scan_id>        # re-scan after code changes; tokens stay stable
localmask hook <scan_id>        # install a git hook to auto-sync on commit
```

Unchanged secrets keep the same placeholder across syncs; new secrets get new ones.

## Git integrations — all the ways

| Integration | Command | What it does |
|---|---|---|
| Scan a local folder | `localmask scan ./repo` | mask secrets on disk |
| Scan a remote repo | `localmask scan https://github.com/org/repo.git` | clone → mask (never stored unmasked) |
| Publish a masked mirror | `localmask publish <scan> <remote-url>` | push a masked copy to any git remote |
| Keep it synced | `localmask sync <scan>` | re-scan on change, tokens stay stable |
| Auto-sync on commit | `localmask hook <scan>` | installs a git `post-commit` / `pre-push` hook |
| Drive it from your AI editor | MCP (below) | assistant calls scan/publish for you |

The remote can be **GitHub, GitLab, Bitbucket, a self-hosted git server, or
Google Secure Source Manager** — any `https://`, `ssh://`, `git@`, or `file://`
remote.

### Private repos (tokens)
For a private source or a private masked mirror, give LocalMask a token:

```bash
localmask store-token                        # prompts for the token HIDDEN,
                                             # stores it encrypted, returns a credential_id
localmask scan https://github.com/org/private.git -c <credential_id>
localmask publish <scan> https://github.com/org/masked.git -c <credential_id>
```

The token is stored encrypted in a local 0600 SQLite file and only a random
`credential_id` is ever passed on the command line — so your token never lands
in your shell history or in `ps`. **Don't** pass the token as an argument
(`store-token ghp_…`): that *does* leak into shell history. You can also rely on
the git credentials already on your machine (e.g. `gh auth login`), or pass
`--token` for a throwaway one-off.

> **You don't need to create the masked repo yourself.** If it doesn't exist,
> `publish` offers to create it for you (private by default) — via a stored
> token or your `gh` CLI login — after asking. Use `--yes` to skip the prompt,
> `--public` to make it public. Use a PAT with **`repo`** scope (or `gh auth`).

## How the git integration stays secure

- **Tokens never touch the URL, process arguments, or `.git/config`.** LocalMask
  authenticates via `GIT_ASKPASS`, so your token isn't visible in `ps`, shell
  history, or the cloned repo's config.
- **Git URLs are validated against an allowlist** (`https/ssh/git@/file`), and a
  `--` separator is placed before them — this blocks argument-injection tricks
  like `--upload-pack=<cmd>` and the `ext::` transport that could run commands.
- **The git username is passed via an environment variable, never interpolated
  into a shell script** — so a hostile username can't inject commands.
- **Only masked content is ever pushed.** The published mirror contains
  `~[TOKEN]~` placeholders; the real values stay in your local vault.
- **Tokens can be stored short-lived and encrypted** (`store-token`), or not
  stored at all (`--token` per command).

## Using AI with LocalMask (free)

Masking and **rehydration are 100% local and deterministic** — they're just a
vault lookup, so they need **no AI and no API key** and are always exact. That
means the free edition works with *any* AI.

### Ask any AI with your own key
```bash
# Save your key once (typed hidden, stored encrypted locally) — then just ask:
localmask set-key anthropic            # prompts hidden; also openai/gemini/grok/groq/…
localmask ask <scan_id> "What are the top risks?" --provider anthropic

# …or pass the key per call:
localmask ask <scan_id> "What are the top risks?" --provider openai   --api-key sk-...
localmask ask <scan_id> "..." --provider anthropic --api-key sk-ant-...
localmask ask <scan_id> "..." --provider gemini    --api-key ...
localmask ask <scan_id> "..." --provider grok      --api-key xai-...
localmask ask <scan_id> "..." --provider groq      --api-key ...    # Meta/Llama
localmask ask <scan_id> "..." --provider openrouter --base-url https://... --api-key ...
```
LocalMask masks the repo + your question locally, sends only `~[TOKEN]~`
placeholders to the provider **you** chose with **your** key, then rehydrates the
answer locally. Keys can also come from env (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GEMINI_API_KEY`, `XAI_API_KEY`, or `LOCALMASK_AI_KEY`). Works with OpenAI,
Anthropic, Google Gemini, xAI/Grok, Meta/Llama (via Groq/Together), OpenRouter,
and any OpenAI-compatible endpoint.

### Or do it by hand — LocalMask never has to call anything
```bash
localmask export <scan_id> ./masked          # write the masked repo to a folder…
#   → point your AI tool / agent at ./masked. No keys, no repo permissions, no secrets.
echo "the AI's answer with ~[TOKEN]~s" | localmask rehydrate <scan_id>   # local, exact
cat prompt.txt | localmask mask-text <scan_id>                          # mask before pasting
```

> The published/exported masked copy contains **no real secrets** — only tokens —
> so it's safe to make the masked mirror **public**, and any AI can read it with
> no credentials. Real values only ever exist in your local vault.

Pro adds the convenience layer: a built-in interactive Ask-AI, the automatic AI
**proxy** (scrub live prompts with zero manual steps), and a local model so you
need no external AI at all — see [localmaskpro.com](https://localmaskpro.com).

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
