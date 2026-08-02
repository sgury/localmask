# LocalMask — Protect Your Code from AI

**How to protect your code from AI: mask secrets and PII before they reach any LLM — 100% locally. Nothing ever leaves your machine.**

Using Cursor, Copilot, Claude, or ChatGPT? Your API keys, passwords, tokens, and PII are sent to external servers with every prompt. LocalMask stops this. It scans your repo, replaces every secret with a safe placeholder like `~[DATABASE_PASSWORD_0]~`, and lets the AI work with tokens instead of real values. When the AI returns code, LocalMask restores the real values — locally.

**GDPR-ready** — supports Data Protection by Design (Article 25) and Data Minimization (Article 5). PII never leaves your machine. [Read the DPIA](https://localmaskpro.com/gdpr).

The free edition is open source and runs entirely offline: 350+ detection patterns
across a regex engine + entropy detection, masking + rehydrate, a publishable masked
repo, git sync, and a CLI + MCP server. No AI model, no cloud, no account.

> Want an AI model that catches what patterns miss and learns from your
> corrections, a web dashboard, the [AI proxy](https://localmaskpro.com) —
> a masking stage in front of your AI (or your company's AI gateway), so
> compliance sees clean prompts and stops blocking developers, and a
> **team-shared vault** so everyone gets consistent tokens?
> See [LocalMask Pro](https://localmaskpro.com).

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

### Security review — a second approval

Masking is the first line; **a second, human approval** stands between a scan
and anything leaving the machine. The developer reviews and edits detections;
then security signs off — nothing publishes unapproved, and a `sync` that
finds new secrets automatically un-approves until re-reviewed. **Auto-approve**
keeps this scalable: scans where every detection clears your confidence bar
(default 95%) flow through automatically; anything uncertain waits for a
human. Every approve/reject decision also teaches the Pro classifier.

Approve either way:

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
and give the AI *its own* read access — LocalMask never shares your git token.
The AI **clones/pulls that repo** (a copy on its side, separate from your real
code) and authenticates as itself. **To get the updated version after you change
code:** `localmask sync <scan>` re-masks and re-pushes the mirror (once approved),
and the AI runs `git pull`. (Because it's masked you *could* also make the mirror
public and skip auth — no secrets are in it.)

*Grant that access in one step — pick how much (if anything) is handed over:*

```bash
# Nothing transferred — the mirror is masked, so just make it public:
localmask grant-ai <scan_id> --public
#   → any AI clones it with NO credential at all.

# Nothing transferred — the AI uses its OWN account:
localmask grant-ai <scan_id> --collaborator <the-ai-bot-username>
#   → grants that account read-only on this repo; the AI signs in as itself.

# A dedicated, throwaway key IS handed to the AI (its own, not yours):
localmask grant-ai <scan_id>
#   → creates a read-only, single-repo SSH deploy key and prints the AI's
#     private key + clone command.
```

**What is and isn't transferred:** LocalMask never shares *your* git token, SSH
key, or account. `--public` and `--collaborator` transfer **nothing** to the AI.
The default deploy-key mode hands the AI a **new, dedicated** credential that is
read-only and scoped to **only** that one repo (a GitHub deploy key can't access
any other repo or your account) — revoke it anytime with `gh repo deploy-key
delete`. If the AI runs on your machine (Claude Code, Cursor), it can just use
the git you already have and you don't need `grant-ai` at all.

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

## Stop secrets before they land — CI & pre-commit

`localmask scan . --fail-on-detection` exits non-zero when it finds a secret, so
it drops straight into any gate.

**Pre-commit** — add to `.pre-commit-config.yaml` (spreads across a team with one line):

```yaml
repos:
  - repo: https://github.com/sgury/localmask
    rev: v0.9.7
    hooks:
      - id: localmask
```

**GitHub Action** — fail a PR that introduces a secret (`.github/workflows/localmask.yml`):

```yaml
name: LocalMask
on: [pull_request]
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sgury/localmask@v0.9.7
```

Both run 100% locally on the runner — nothing leaves it.

## Route your AI tool through the masking proxy (Pro)

One command points Claude Code / Cursor at the local proxy, so prompts are masked
on your machine before anything is sent to the AI (or to your org's AI gateway):

```bash
localmask proxy setup claude-code   # or: cursor · codex · env
localmask proxy                     # start it (Pro)
```

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

## Finance Mode — AI analysis of financials without the figures

Teams that won't paste salaries, prices or revenues into an AI get no AI help
on exactly the data that matters most. Finance Mode fixes that.

Three modes (set via `LOCALMASK_MONEY_MODE`):

| Mode | What the AI sees | Use when |
|---|---|---|
| `token` | `~[AMOUNT_0]~` | full opacity — AI can't see any relationship |
| `bucket` | `~[AMOUNT_5D_USD_0]~` | order of magnitude only (5-digit USD amount) |
| `relative` | `(1.15*R_AMOUNT)` | AI can compare and compute ratios |

**Relative mode** — how it works:
1. LocalMask generates a secret random base `R` on your machine (stored in
   `~/.localmask/money_keys.json`, 0600, never uploaded).
2. Every amount becomes a ratio to that base: `$42,000` → `(0.42*R_AMOUNT)`.
3. The AI can compare and compute ("Dana earns 20% more than John") but never
   sees the real figures, currency, or scale.

```bash
LOCALMASK_MONEY_MODE=relative localmask scan .
```

| What's on disk | What the AI sees |
|---|---|
| `salary Dana: $42,000` | `salary Dana: (1.20*R_AMOUNT)` |
| `salary John: $35,000` | `salary John: (1.00*R_AMOUNT)` |
| `revenue: $8,500,000` | `revenue: (242.86*R_AMOUNT)` |

**What's hidden:** the amounts, the currency, the scale.
**What's visible:** ratios between amounts — that's the analysis you asked for.
**R:** generated with a CSPRNG on your machine, stored locally, never uploaded.

Only currency-anchored or finance-keyword-anchored numbers are touched — bare
numbers (ports, versions, IDs) never are. The vocabulary is editable in
`regex_patterns.json` (add your own domain terms, no code). Full details and
the honest threat model: [FINANCE.md](FINANCE.md).

Finance Mode is **free and open source**. Locking the mode org-wide is Pro / Team.

## Multilingual detection — 9 language packs

Secrets and PII don't only hide in English. LocalMask ships keyword patterns
for **Romanian, Hebrew, Russian, Arabic, Spanish, French, German, Italian,
and Hindi**:

```text
// CNP: 1850301401008             ← Romanian CNP, checksum-validated
# parola: Bucur3sti!9x            ← password labeled in Romanian
# ת"ז של הלקוח: 234569176        ← Israeli ID, check-digit validated
# пароль: S3cur3!Pass74           ← password labeled in Russian
; DNI: 12345678Z                  ← Spanish DNI, control-letter validated
// كلمة المرور: Xk9$mPl2Qw        ← password labeled in Arabic
```

National IDs are checksum-validated (a random 13-digit number near "CNP"
does NOT match), and every pattern is word-boundary guarded so digits inside
a longer key or hash never fire. Pick packs with `LOCALMASK_LANGS=he`
(default: none — opt in to avoid unexpected FPs from languages you don't use).

**Edition note:** **Hebrew (`he`) is free.** All other language packs
(ro, ru, es, ar, de, fr, it, hi) require [LocalMask Pro](https://localmaskpro.com).
A clear upgrade notice is printed if a gated pack is loaded without a license;
detection falls back to free packs automatically. Adding a language is a JSON
block in `regex_patterns.json` — no code.

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
This default (`--source memory`) masks the repo + your question locally and
sends only `~[TOKEN]~` placeholders to the provider **you** chose with **your**
key, then rehydrates the answer locally. Keys can also come from env
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `XAI_API_KEY`, or
`LOCALMASK_AI_KEY`). Works with OpenAI, Anthropic, Google Gemini, xAI/Grok,
Meta/Llama (via Groq/Together), OpenRouter, and any OpenAI-compatible endpoint.

### Let the AI read the masked git itself — don't ship the repo (`--source git`)

If the AI/agent already has its **own** read access to the published masked
mirror, you don't need to send it the code at all:

```bash
localmask ask <scan_id> "Why does <a secret in your question> fail?" --source git
#   --git-url <url>   (defaults to the scan's published mirror)
```

LocalMask **masks only your question** (by the found-secret vault — any real
secret you type becomes a token), sends just that masked question **plus the repo
URL** to your AI, and the AI **reads the private masked repo itself** with its own
grant. The answer is rehydrated locally. **No repo content and no git credentials
leave your machine** — only the masked question. (Best with agent/tool-capable
AIs that can clone a repo. For the MCP/agent flow, the same thing is exposed as
the `mask_prompt` and `rehydrate_answer` tools.)

### Or do it by hand — LocalMask never has to call anything
```bash
localmask export <scan_id> ./masked          # write the masked repo to a folder…
#   → point your AI tool / agent at ./masked. No keys, no repo permissions, no secrets.
echo "the AI's answer with ~[Token]~s" | localmask rehydrate <scan_id>   # local, exact
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
| Regex + entropy engine, 350+ patterns | ✓ | ✓ | ✓ |
| SQL query value masking | ✓ | ✓ | ✓ |
| Editable pattern rules (`regex_patterns.json`) | ✓ | ✓ | ✓ |
| Mask / rehydrate | ✓ | ✓ | ✓ |
| Persistent local vault (stable tokens, encrypted) | ✓ | ✓ | ✓ |
| Edit detections (ignore / teach) | ✓ | ✓ | ✓ |
| Publish masked repo + git sync | ✓ | ✓ | ✓ |
| Finance Mode (token / bucket / relative) | ✓ | ✓ | ✓ |
| CLI + MCP server | ✓ | ✓ | ✓ |
| LLM classifier (catches what regex misses, learns from corrections) | — | ✓ | ✓ |
| Comment scanner (finds PII inside code comments via LLM) | — | ✓ | ✓ |
| Web dashboard | — | ✓ | ✓ |
| AI proxy — masking before your AI / gateway | — | ✓ | ✓ |
| Team-shared vault (consistent tokens across machines) | — | — | ✓ |
| Org shared rules · LDAP/AD · SSO | — | — | ✓ |

## Detection accuracy

Benchmarked against real-world datasets:

- **CredData** (Samsung, 297 repos, 4,583 labeled credentials): F1 **42%** — ahead of
  gitleaks (33%), truffleHog3 (24%), detect-secrets (21%) on the same corpus.
- **AI4Privacy** (2,000 validation samples, 17 PII types): F1 **61.6%** — 100% precision
  on email, phone, credit card; recall gaps on international ID formats.

Full methodology and per-category breakdowns: [BENCHMARK-REAL-CORPUS.md](BENCHMARK-REAL-CORPUS.md).

## Feedback

Found a false positive, a missed secret, or have a feature request?
Email **feedback@localmaskpro.com** or open an issue at
https://github.com/sgury/localmask/issues — we read everything.

## License

Free edition released under the MIT license. See `LICENSE`.
