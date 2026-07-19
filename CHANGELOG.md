# Changelog

All notable changes to LocalMask. Dates are release dates.

## 0.9.5 — 2026-07-19

Detection precision release: -49% false positives on the 11-repo test suite,
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
