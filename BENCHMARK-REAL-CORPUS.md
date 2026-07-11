# Real-corpus benchmark (2026-07-11) — honest findings

Ran LocalMask 0.9.3 vs gitleaks 8.30, detect-secrets 1.5, trufflehog 3.95
(static `--no-verification`) on **4 real, popular OSS repos** (shallow clones):
`psf/requests`, `pallets/flask`, `expressjs/express`, `gin-gonic/gin`.

These repos have **no ground truth** — there is no manifest of "real" secrets.
So a detection is NOT automatically a false positive: much of what every tool
flags is **secret-shaped test/doc data** (fake tokens, `user:pass@host` URLs,
auth examples). `requests` is worst-case here — it's an HTTP-auth library whose
test suite is full of credential examples.

## Raw detections per repo

| repo | LocalMask secret-type | LocalMask PII (email) | gitleaks | detect-secrets | trufflehog |
|------|----------------------:|----------------------:|---------:|---------------:|-----------:|
| requests | 17 (free) / 13 (Pro) | 64 | 4 | 15 | 34 |
| flask    | 11 | 4 | 6 | 23 | 0 |
| express  | 8  | 15 | 0 | 35 | 0 |
| gin      | 4  | 6 | 4 | 4 | 1 |

(LocalMask numbers are true-free/regex unless noted; the Pro classifier trims a
few infra-ID types — on `requests`, 17→13 by dropping IPv6/IP/UNC-path guesses.)

## What this means — read before publishing any comparison

1. **On real code, raw counts ≠ false positives.** Nearly all of these hits are
   secret-shaped fixtures in test/doc code. Every tool flags them. You cannot
   honestly call them FPs without ground truth.

2. **LocalMask's headline volume is PII, not secrets.** On `requests`, 64 of 81
   detections are contributor **emails** — a capability gitleaks / detect-secrets
   / trufflehog **do not have at all**. That's a differentiator, not noise.

3. **On secret-type detections, LocalMask is in the same ballpark** as the others
   on real repos — it is NOT dramatically "cleaner" the way the synthetic suite
   implied. `requests`: LM 13–17 vs gitleaks 4 / detect-secrets 15 / trufflehog
   34. LocalMask sits mid-pack, well below trufflehog/detect-secrets, above
   gitleaks on some.

4. **The "LocalMask 5 decoy-FPs vs detect-secrets 44" number is real but
   suite-specific.** It came from our 11 synthetic ground-truth repos, where FP
   is measurable. It is NOT a universal real-world figure.

## Marketing guidance (honest positioning)

- **Do** lead with what's uniquely true: **100% local / no phone-home**, **PII +
  8-language detection** (the others do zero PII), and the **AI-proxy masking**
  flow. These are real, defensible, and unique.
- **Do** cite the precision number **scoped**: "on our 13-repo benchmark suite,
  LocalMask had 5 decoy false-positives vs detect-secrets' 44" — never as a bare
  "fewer false positives than X in the real world."
- **Don't** publish a raw real-repo "FP" comparison — it's not FP without ground
  truth, and on auth-heavy code LocalMask flags plenty (correctly).

## Home-turf benchmark — testing on gitleaks' OWN vendor catalog (2026-07-11)

The best "where do we improve" test: run LocalMask against the vendor secrets
**gitleaks itself is built to catch**. Extracted gitleaks' 222 rules, generated
an example per rule, kept the ones gitleaks self-detects (75 vendors), and
measured LocalMask's coverage.

- **Before:** LocalMask caught **44 / 75 = 59%** of gitleaks' validated vendors.
- The ~21 real gaps were mid-tier SaaS vendors LocalMask lacked patterns for.
- **Added 9** distinctive-prefix, low-FP vendor patterns (verified 8/8 catch a
  clean canonical token, 0 FP on real repos, gate unchanged):
  DigitalOcean `dop_v1_`, GitLab incoming-mail `glimt-` / SCIM `glsoat-` /
  runner `glrt-`, Heroku v2 `HRKU-AA`, Clojars `CLOJARS_`, Linear `lin_api_`,
  Airtable PAT `pat…`, HashiCorp TF `…atlasv1…`.
- **Still-open gaps** (~12, keyword-context → higher FP, add carefully): Dropbox,
  Discord, DroneCI, Kraken, Codecov, Etsy, HubSpot, Intercom, Bitbucket
  client-id, Cloudflare global key, Harness, JWT-base64.

### Vendors added (2026-07-11) — all overlap-checked, 0 FP, gate unchanged
26 vendor patterns added this pass, each verified by an **overlap-safety checker**
(canonical token with a distinct value → detected as ITS OWN type, never
misclassified into another category):
- Distinctive-prefix: DigitalOcean, GitLab (mail/scim/runner), Heroku v2,
  Clojars, Linear, Airtable, HashiCorp TF, Square, Mailchimp, Harness, Notion,
  Mailgun, Figma.
- Keyword-anchored: Dropbox, Discord, DroneCI, Codecov, HubSpot, Intercom,
  Bitbucket client-id, Cloudflare global.

Still open (keyword-context, higher FP — add carefully): Auth0, Snowflake,
Vercel, Fastly, Linode, Kraken, Etsy. (JWT already caught as `jwt_token`.)

### Modern-vendor pass (2026-07-11, commits 5181bba canonical / 25a124d OSS)
Re-audited with CANONICAL-LENGTH tokens (the earlier synthetic tokens were the
wrong length and fell through to the generic `secret` catch — a measurement
artifact, not a real miss). True misses found and closed, all distinctive-prefix
(overlap-verified: each types as its own type; `sk-ant-` stays anthropic, legacy
`sk-[48]` stays openai_key; 0 FP on the 4 real repos; gate byte-identical):
- **OpenAI project/service/admin keys** (`sk-proj-`/`sk-svcacct-`/`sk-admin-`) —
  IMPORTANT: the legacy `openai_key` rule `sk-[a-zA-Z0-9]{32,}` misses EVERY
  modern OpenAI key because the dash after `proj`/`svcacct` breaks `{32,}`.
  Modern keys are all this format now. New rule `openai_project_key`.
- **Okta** API token (`SSWS ` scheme — Okta-exclusive, safe to keep the token
  part permissive).
- **Groq** (`gsk_`), **Perplexity** (`pplx-`), **Sentry auth** (`sntry[su]_`).
- **Doppler** widened from `dp.pt.` only to service/service-account/CLI/scim/
  audit token types (`dp.(pt|st|sa|ct|scim|audit).`).
LESSON: always re-test vendor coverage with a CANONICAL-length token — a generic
`secret`/`py_hardcoded_secret` type means the specific rule didn't match (often
just wrong test length), NOT that the value is unprotected.

**This is the method to repeat:** cross-test against each competitor's own rule
catalog periodically — it surfaces exactly which real vendors you're missing.
GOTCHA: when overlap-checking, use a DISTINCT value per vendor — identical test
tokens (e.g. reused `a(32)`) make one string match several patterns and falsely
flag a collision.
Caveat: an auto-generated corpus is noisy (exrex fills keyword-context with
junk); validate patterns against clean canonical tokens, not the noisy corpus.

## For a real RECALL number (future work)

This run measured behavior on clean-ish real code (a precision proxy). A true
real-world **recall** number needs a corpus with known planted/leaked secrets
(SecretBench academic dataset, or a curated set of real-format keys in real
repos). SecretBench is gated/large — obtain access before making recall claims.

## Reproduce

Tools: `gitleaks`, `trufflehog` (brew), `detect-secrets` (pip venv). Clone the 4
repos shallow; per repo:
- LocalMask: `LOCALMASK_EDITION=free OLLAMA_HOST=http://127.0.0.1:1 localmask scan <repo>`
- gitleaks: `gitleaks dir <repo> -f json -r out.json`
- detect-secrets: `cd <repo> && detect-secrets scan --all-files .`
- trufflehog: `trufflehog filesystem <repo> --no-verification --json`
Strip ANSI before parsing LocalMask's count (that bit me — a colored "81" parsed
as "0" on the first pass).
