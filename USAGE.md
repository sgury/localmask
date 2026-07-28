# LocalMask Pro — Usage Guide

LocalMask Pro detects and masks sensitive data (secrets, PII, credentials) in code repos before sharing them with AI or publishing externally. Real secrets never leave the server.

---

## Architecture

```
Developer (CLI)  ──>  LocalMask Server (Cloud Run)  ──>  AI Provider
                         |                                    |
                    Scans repos              Sees only masked tokens
                    Stores vault             e.g. ~[PASSWORD_0]~
                    Masks secrets            Never sees real values
```

- **Server** — runs on GCP Cloud Run (or locally). Handles scanning, masking, vault storage, and AI chat.
- **CLI** — thin client on the developer's machine. Communicates with the server over HTTPS.
- **Web UI** — security dashboard at the server URL for managers to approve/reject scans.

---

## Installation

### Install the CLI

```bash
# From the LocalMask Pro directory:
bash install-cli.sh

# Restart terminal, then:
localmask --help
```

Or use directly without installing:
```bash
python cli.py --help
```

### Deploy Server to GCP

```bash
# Requires: gcloud CLI authenticated with a project
bash deploy-gcp.sh
```

This builds a Docker image, pushes to Container Registry, and deploys to Cloud Run. The output gives you the server URL.

### Run Server Locally

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python server.py
# Server starts at http://localhost:8000
```

---

## Developer Workflow (CLI)

### 1. Connect to the server

```bash
localmask connect https://localmask-pro-xxx-uc.a.run.app
# or for local:
localmask connect http://localhost:8000
```

### 2. Store your GitHub token (for private repos)

```bash
localmask store-token "ghp_yourTokenHere"
```

The token is sent once over HTTPS and stored server-side. You get a `credential_id` saved locally for future scans.

### 3. Set your AI API key

```bash
localmask set-key anthropic "sk-ant-api03-yourKeyHere"
# or:
localmask set-key openai "sk-yourKeyHere"
localmask set-key gemini "AIza-yourKeyHere"
```

### 4. Scan a repo

```bash
localmask scan https://github.com/org/repo

# For private repos (uses saved token automatically):
localmask scan https://github.com/org/private-repo

# With explicit credential:
localmask scan https://github.com/org/repo -c cred_xxx

# Sensitivity levels: minimal, standard (default), strict
localmask scan https://github.com/org/repo -s strict
```

### 5. Check status

```bash
# List all scans:
localmask status

# Detail for one scan:
localmask status <scan_id>
```

### 6. Review detections

```bash
# Interactive review (approve/reject each finding):
localmask review <scan_id>

# Or quick-approve everything:
localmask approve-all <scan_id>
```

The interactive reviewer shows a 3-level hierarchy: Type > Instances > Single detection. Navigate with keyboard shortcuts shown on screen.

### 7. Submit for security approval

```bash
localmask submit <scan_id>
```

This moves the scan to "submitted" status. The security team reviews it in the web dashboard.

### 8. Publish masked repo

After the security team approves:

```bash
localmask publish <scan_id> https://github.com/org/repo-masked --token "ghp_xxx"

# Or using saved credential:
localmask publish <scan_id> https://github.com/org/repo-masked
```

This pushes the masked version of the code to the target git remote. All secrets are replaced with tokens like `~[PASSWORD_0]~`.

### 9. Ask AI about the code

```bash
# Interactive chat:
localmask ask <scan_id>

# Single question:
localmask ask <scan_id> "what does the auth module do?"

# Choose provider:
localmask ask <scan_id> --provider openai --model gpt-4o

# Ask from published masked git repo:
localmask ask <scan_id> --source git --git-url https://github.com/org/repo-masked
```

The AI only sees masked content. When it responds, tokens are rehydrated back to real values for the authorized reviewer.

---

## Security Manager Workflow (Web UI)

The Security Dashboard is the web interface where security managers review, approve, or reject scans submitted by developers.

### Accessing the Dashboard

Open the server URL in a browser:
```
https://localmask-pro-xxx-uc.a.run.app
```
Click the **Security Dashboard** tab at the top.

### Step 1: View Submitted Repositories

The dashboard shows a table of all scans: **Repositories Pending Review**.

Each row shows:
- **Repo URL** — the scanned repository
- **Scan ID** — unique identifier
- **Status** — draft / submitted / under_review / approved / rejected / published
- **Detections** — number of secrets found
- **Submitted By** — which developer submitted it

Click **Refresh** to reload the list. Click any row to open the scan detail.

### Step 2: Review Detections

When you select a scan, the detail panel opens showing:

- **Status Stepper** — visual workflow: draft → submitted → under_review → approved → published
- **Detection Table** with columns:
  - **#** — detection number
  - **File** — source file path
  - **Line** — line number
  - **Type** — detection type (PASSWORD, API_KEY, EMAIL, etc.)
  - **Detected Value** — the actual secret (visible only to security manager)
  - **Token** — the mask token (e.g. `~[PASSWORD_0]~`)
  - **Engine** — which detector found it (regex, NER, classifier)
  - **Conf** — confidence score
  - **LLM Verdict** — AI classification result (SENSITIVE / NOT_SENSITIVE)
  - **Decision** — dropdown to approve/reject each individual detection

### Step 3: Make Individual Decisions (Optional)

For each detection in the table, use the **Decision** dropdown to:
- **Approved** — confirm this is a real secret and should be masked
- **Rejected** — mark as false positive (won't be masked)
- **Pending** — not yet decided

### Step 4: Bulk Actions

At the bottom of the detail panel:

| Button | Action |
|--------|--------|
| **Open & Review** | Opens the scan in the main editor view for side-by-side review of original vs. masked content |
| **Approve Repo** | Approves the entire scan. After approval, a publish form appears to push the masked repo to a git remote |
| **Reject Repo** | Rejects the scan. Requires a comment explaining the rejection reason |

Use the **Comment** text box to leave notes for the developer (optional for approval, required for rejection).

### Step 5: Publish (After Approval)

After clicking **Approve Repo**, a publish form appears:
1. Enter the **target git repo URL** (e.g. `https://github.com/org/repo-masked`)
2. Optionally enter a **git username**
3. Enter a **PAT / token** for push access (or leave empty to use the scan's stored credential)
4. Click **Publish**

The masked code is pushed to the target repo. All real secrets are replaced with tokens.

### Security Reports

Below the scan detail, the **Security Reports** section shows aggregate statistics:
- Total scans processed
- Approval/rejection rates
- Detection type breakdown across all scans

Click **Refresh Reports** to update.

---

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `connect <url>` | Connect to a LocalMask server |
| `store-token <token>` | Store git PAT on server, get credential_id |
| `set-key <provider> <key>` | Set AI API key (anthropic/openai/gemini) |
| `scan <repo-url>` | Scan a repo for secrets |
| `status [scan_id]` | List all scans or show one scan's detail |
| `review <scan_id>` | Interactive 3-level review |
| `approve-all <scan_id>` | Approve all detections and submit |
| `submit <scan_id>` | Submit for security team approval |
| `publish <scan_id> <url>` | Push masked repo to git remote |
| `ask <scan_id> [question]` | AI chat about masked code |

---

## How Masking Works

1. **Scan** — RegEx + NER + AI classifier detect secrets, PII, credentials
2. **Mask** — Each secret gets a unique token: `~[PASSWORD_0]~`, `~[API_KEY_1]~`
3. **Vault** — Bidirectional mapping (token <-> real value) stored server-side only
4. **Publish** — Masked files pushed to git. No real secrets in the repo.
5. **AI Chat** — Questions are masked before sending to AI. Answers are rehydrated after.

Key names, config labels, SQL columns, and infrastructure terms are protected from false-positive masking using structural key-value pattern recognition.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOCALMASK_HOST` | `127.0.0.1` | Server bind address |
| `LOCALMASK_PORT` | `8000` | Server port |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama URL (optional local LLM) |
| `OLLAMA_MODEL` | `llama3.1:8b` | Ollama model name |

---

## Cleanup

```bash
# Delete Cloud Run service:
gcloud run services delete localmask-pro --region us-central1 --quiet

# Delete container image:
gcloud container images delete gcr.io/YOUR_PROJECT/localmask-pro --quiet
```
