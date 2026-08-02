---
name: scan-and-mask
description: Scan a repository for secrets and PII, review findings, and mask everything before AI sees it.
---

# Scan and mask

## When to use

- When opening a new project for the first time
- When the user asks to scan for secrets or protect their code
- Before sharing code with AI tools

## Instructions

1. Call `scan_repo` with the repository path to find all secrets, API keys, passwords, tokens, connection strings, and PII.
2. Present the scan results to the user — show how many findings per file.
3. Use `get_review_queue` to show pending detections that need approval.
4. For each detection, the user can approve (mask it) or reject (keep readable) using `review_detection`.
5. Use `bulk_review` to approve or reject multiple detections at once.
6. After review, all approved secrets are masked as `~[TOKEN_N]~` placeholders.
7. From now on, use `read_file_masked(path)` to read any file — you'll see tokens instead of real values.
