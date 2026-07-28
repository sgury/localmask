# 0.9.9 (2026-07-28)

- In-editor review: `localmask decide approved|rejected --file <path> [--line N]`
  — non-interactive decisions addressed the way editors think (file+line)
- File-scoped lexicon: rejecting a whole FILE keeps its values readable only
  in that file — the same value elsewhere in the repo stays masked
- Taught values always mask: the key-position guard can no longer swallow a
  user-taught value inside name="…" attributes (teach is instant now)
- `teach --stdin`: IDE integrations pass values over stdin — never argv,
  never shell history
- VS Code extension 0.2.0: Problems-panel review with lightbulb
  approve/reject, inline state highlights, review sidebar (value-first),
  right-click teach-by-marking, real⇄masked diff, on-save sync, custom teach
  categories — every surface opt-in with its own setting
- New: JetBrains plugin (PyCharm/IDEA/DataGrip) — status-bar shield + action
  menu + read-only masked view; source ships in all editions
- Fix: `.env` and other dotfiles were unaddressable in file review commands

# 0.9.8 (2026-07-28)

- Instant masked views: scans/syncs persist masked content; mask-text and the
  VS Code key toggle serve it in ~0.5s; review decisions update it immediately
- VS Code extension shipped in ALL edition tarballs: shield menu (scan/sync,
  approve, publish, review, teach hidden-input, hook), stage badge, key toggle
  for every file type
- Local-only review: reject-file/approve-file, reviewer Files view, durable
  lexicon rejections (survive re-scans); teach needs no scan id
- .localmaskignore: gitignore-style scan exclusions (excluded = never scanned,
  never published); scan summary reports the count
- MCP hardening: teach tool removed (no secret values through chat),
  get_file_masked sanitization, deterministic review board with clickable
  refs, bulk_review per-file form, latest-scan defaults; init writes AI-guard
  deny rules (.claude/settings.json) blocking raw reads
- Detection: ConvertTo-SecureString/PSCredential passwords, SMTP password
  assignments, single-segment SendGrid keys, SQL finance-column numerics
- Fix: update hint only for strictly newer published versions

# Changelog

All notable changes to LocalMask. Dates are release dates.

## 0.9.7 — 2026-07-27

Detection coverage + IDE release: the LLM gate can no longer veto pattern
rules, strict-mode coverage extended to infra values, and a VS Code key-toggle
extension for flipping any file between real and masked view.

### Fixed
- **LLM gate no longer drops deterministic pattern-rule detections** — the
  classifier may only demote heuristic hits (entropy, NER). It was silently
  un-masking real infra values the regex layer had already caught (SQL DECLARE
  server/API literals, JSON `database`/`port` fields). Fail-safe = mask.
- **Scan sensitivity is persisted** (`summary_stats.sensitivity`) — `sync` and
  `mask-text` re-scan at the sensitivity the user chose. Both previously fell
  back to `standard`, so strict-level rules vanished on every re-scan.
- **`mask-text` uses the real file name and scan sensitivity** — file-type rule
  packs (xml/.config, json, sql, …) only fire for the right extension; scanning
  as `input.txt` lost them. Loader/status prints moved off stdout so consumers
  (the VS Code extension) get clean masked content.
- **`swift_bic` keyword-anchored** — at strict it matched any 8/11-char
  uppercase word (68 false positives on one repo).

### Added
- **VS Code extension: LocalMask Key Toggle** (`integrations/vscode-localmask/`)
  — a status-bar 🔑 (Cmd+Alt+K) flips the active editor between real values and
  a read-only masked view via `localmask mask-text`. Scan id auto-detected from
  the repo's LocalMask git hook.
- **New pattern rules**: `xml_db_attr` (Initial Catalog / Database in
  connection strings), `sql_declare_secret` + `sql_declare_infra` (secret and
  server/endpoint literals in SQL DECLARE), `json_port`, and a universal
  `internal_url` rule (URLs on internal/corp hosts).
- **CSV/TSV support with deterministic column masking** — data files are now
  scanned (previously skipped entirely). Every cell in a column whose header
  names a PII/finance field (name, email, phone, ssn, card, iban, address,
  salary, balance, amount, sum, total, …) is masked — no checksum or model
  recall in the loop, so a data extract can't leak on a miss. Columns the
  header doesn't identify are classified ONCE from 2-3 sample values (columns
  are homogeneous — no per-cell detection), then masked column-wide. Person
  names in free cells are additionally caught by NER. Free-TEXT columns the
  patterns can't decide go to the local LLM (CommentScanner machinery, new
  data-extract prompt: health, ethnicity, names, finances…): if samples come
  back sensitive, ALL values are examined and only the sensitive substrings
  are masked — prose stays readable, secrets don't. 100% local.

## 0.9.5 — 2026-07-19

Detection precision release: -48% false positives on the 11-repo test suite,
detection rate held at 99%.

### Changed
- **Stripe publishable keys (`pk_live_`, `pk_test_`) no longer flagged** —
  publishable keys are public by design; only secret keys (`sk_live_`, `sk_test_`)
  are sensitive. Both the prefix map and the entropy-scanner fallback updated.
- **System / robot email addresses excluded** — `no-reply@`, `notifications@`,
  `mailer@`, `devops@`, `deploy@`, and GCP service-account domains
  (`.gserviceaccount.com`) are now skipped by the email pattern.
- **Database URLs without embedded credentials no longer flagged** —
  `postgresql://host/db`, `mysql://host/db`, `redis://localhost` (no `@`) are
  excluded from `db_connection_url` and the entropy-scanner non-secret filter.
- **Twilio Account SIDs (`AC` + 32 hex) excluded** — public identifiers, not secrets.
- **JDBC URLs require embedded credentials** — `jdbc:postgresql://host/db`
  (no `user:pass@`) is no longer flagged.
- **`connstr_userid_inline` removed** — DB usernames in connection strings are
  not secrets; the password in the same string is caught by other patterns.
- **`url_embedded_password` skips placeholder passwords** — `dev_pass`,
  `test_pass`, `dummy_pass`, and similar prefixes excluded.
- **`password_assignment` smarter** — skips variables named `*template`,
  `*message`, `*subject` and values in SendGrid template-ID format (`d-[hex]`).
- **`unquoted_env_secret`** — minimum value length raised 8 → 10; `$`, `(`, `)`
  excluded (prevents `$(openssl rand …)` and Python type annotations matching).
- **`password_unquoted`** — positive lookahead now requires at least one digit
  or special character, excluding pure-identifier variable references.
- **`bitcoin_address`** — length range tightened `{25,45}` → `{25,33}` to avoid
  40-character git SHA collisions.
- **`prose_password` / `prose_credential`** — minimum length raised, extra
  punctuation excluded from captured values.
- **`prose_ip_address`** confidence lowered 0.88 → 0.70 (LLM reviews tutorial IPs).
- **`git_config_username` / `git_config_email`** confidence lowered 0.95 → 0.75
  (LLM can dismiss CI bot committer identities).
- **`base64_encoded_secret` removed from LLM skip-list** — weak base64 blobs
  (confidence 0.8, only a secret-named field, no decoded credential found) now go
  through the LLM gate; strong blobs (confidence 0.9, decoded secret found) still
  skip via the ≥ 0.9 threshold.
- **Known false-positive values added** — `smtp.gmail.com`, `smtp.office365.com`,
  `smtp.sendgrid.net`, `svc_api`, `test-jwt-secret-not-for-production`,
  `AKIAIOSFODNN7TESTING`, `AKIAIOSFODNN7EXAMPLE`.
- **`unquoted_env_secret` now detects env vars inside Python/YAML strings** —
  `"PGPASSWORD=Str0ng!Db2024"` and similar patterns (env var embedded in a string
  literal inside a test list or config) are now detected. Previously, the `^`
  line-start anchor prevented any match when the env var was preceded by a quote.
  Fixed by allowing the match after a quote character (`(?:^|(?<=['"]))`).

### Pro
- **LLM context now includes file path** — every detection sent to the Ollama
  classifier is prefixed with `[rel/path/to/file]` so the model can distinguish
  test fixtures and documentation from production configs.
- **Classifier prompt v4** — added explicit file-path instruction and five
  targeted not-sensitive examples (Stripe `pk_live_`, Twilio Account SID,
  test-conftest password, doc placeholder, bare JDBC URL).
- **`retrain()` type-accuracy metric fixed** — replaced broken LLM-sampling
  approach (always returned 0.0%) with a label-coverage metric that requires no
  LLM calls and correctly measures recognised-type coverage.
- **Cache version bumped to v4** — invalidates verdicts built without file-path
  context so old cached results don't mix with new ones.

---

## 0.9.4 — 2026-07-12

### Fixed
- **Free-edition install error** — `netpolicy.py` was missing from the free
  wheel; importing `cli` or `licensing` would raise `ImportError`. Added to the
  free file set in `build-dist.sh`.

### Added
- **Release QA harness** (`qa/release-qa.sh`) — one command runs the full
  release matrix: unit suite, detection regression gate, mask-integrity check,
  build all four editions, free fresh-install in a clean venv, signed-license
  capability matrix, live-Ollama Pro-value check, and Team/Ent E2E. Writes
  `qa/QA-REPORT.md`. `qa/CHECKLIST.md` covers manual UX surfaces.
- **`/license?session_id` webhook endpoint** — caches the issued key against
  the Stripe checkout-session ID (1 h TTL) so the post-purchase `/success` page
  can display the key immediately; email remains the durable delivery channel.

### Changed
- **Ask-AI gated to Pro+** — `localmask ask` and the MCP `ask_about_scan` tool
  now require an active Pro license and return a clean upgrade message on Free,
  instead of a usage-limited fallback.
- **Classifier described accurately** — README copy no longer claims the Ollama
  model catches secrets that regex misses. The classifier is precision-only: it
  demotes ambiguous detections to cut false positives; recall comes from the
  always-on regex / NER / entropy layers.

---

## 0.9.3 — 2026-07-10

Licensing, distribution, and CI/editor integrations. The detection engine is
unchanged from 0.9.2 (100% detection, 0 missed on the test suite).

### Added
- **`localmask scan --fail-on-detection`** — exit non-zero when a secret or PII
  is found, so a scan can gate a commit or a CI run.
- **pre-commit hook** (`.pre-commit-hooks.yaml`) — add LocalMask to a repo's
  `.pre-commit-config.yaml` in four lines; blocks commits that contain secrets.
- **GitHub Action** (`sgury/localmask@v0.9.3`) — fails a pull request that
  introduces a secret. Runs 100% locally on the runner.
- **`localmask proxy setup claude-code|cursor|codex|env`** — one command points
  an AI tool at the local masking proxy (Pro).
- **`localmask check-updates`** — opt-in check for a newer version. LocalMask
  never contacts the network on its own; scanning stays fully offline.

### Changed
- **New license system (LM2).** Licenses are Ed25519-signed and validated 100%
  offline. Pro is now a **one-time purchase**: every version released within
  your 12-month update window is yours to run forever.
- **Paid editions now ship readable source** (no compiled `.pyc`). Fixes
  Python-version fragility and lets you review every line that runs on your code.
- Version reporting is now correct across pip, git, and source installs.

### Security
- Paid capabilities unlock only on a valid **signed license**, not on the
  editable edition flag — editing the shipped source cannot unlock Pro.

## 0.9.2 — 2026-07-09

### Added
- **Finance Mode** — mask monetary amounts (`token` / `bucket` / `relative`).
  `relative` (ratio-to-a-secret-base) is free; the opacity choice is Pro. Runs
  only when you turn it on; off by default.
- **Web dashboard settings** — choose Finance Mode and detection languages in
  the UI. Team/Enterprise can lock these org-wide.
- **Romanian language pack** (CNP checksum-validated) — 8 language packs total
  (Hebrew, Russian, Arabic, Spanish, French, German, Italian, Romanian) with
  national-ID and phone validators.

### Changed
- Detection vocabulary (money keywords, categories) is data-driven — extend it
  in config without code changes.

### Fixed
- A sentence-ending period no longer splits an amount or blocks a mask.

## 0.9.1 — 2026-07-08

### Added
- `localmask feedback` and a contact address (feedback@localmaskpro.com).
- PyPI install tracking.
