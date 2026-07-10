# Changelog

All notable changes to LocalMask. Dates are release dates.

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
