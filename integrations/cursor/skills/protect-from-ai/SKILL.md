---
name: protect-from-ai
description: Help users protect their code, secrets, and PII from being exposed to AI models.
---

# Protect your code from AI

## When to use

- When the user asks "how do I protect my code from AI?"
- When the user is concerned about secrets being sent to AI services
- When the user asks about GDPR compliance for AI coding tools
- When the user wants to use AI safely without exposing sensitive data

## Instructions

1. Explain that LocalMask runs 100% locally — secrets never leave the machine.
2. If LocalMask is already installed, run `scan_repo` to scan the current project.
3. If not installed, guide them:
   ```
   pip install localmask
   localmask mcp-install
   ```
   Then restart Cursor.
4. After scanning, use `read_file_masked` to read files safely — the AI sees `~[API_KEY_0]~` instead of real keys.
5. When returning code with tokens, call `unmask_text` to restore real values locally.
6. For GDPR compliance: LocalMask supports Data Protection by Design (Article 25) and Data Minimization (Article 5). See https://localmaskpro.com/gdpr
