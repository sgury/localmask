---
name: review-and-publish
description: Review scan findings and publish a masked mirror of the repository to a separate git remote.
---

# Review and publish

## When to use

- When the user wants to publish a safe, masked version of their repo
- When setting up a masked git mirror for CI/CD or external collaboration
- When the user wants to share code without exposing secrets

## Instructions

1. Check scan status with `get_review_queue` — all detections must be reviewed before publishing.
2. Use `bulk_review` to approve remaining detections, or review individually with `review_detection`.
3. Call `publish_masked_repo` with the scan ID and target git URL to push the masked version.
4. Optionally, call `setup_git_hook` to install a post-commit hook that auto-syncs the masked mirror on every commit.
5. The published repo contains only `~[TOKEN_N]~` placeholders — no real secrets ever leave the machine.
6. Use `sync_repo` to manually re-sync after changes if no hook is installed.
