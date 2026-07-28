# 📋 LocalMask Pro - Setup Guide

## Prerequisites

- **Python 3.8+** (check: `python --version`)
- **pip** (comes with Python)
- **~1GB free disk space** (for models)
- **~1GB RAM** (DistilBERT inference)

## Step-by-Step Setup

### Step 1: Navigate to Project

```bash
cd localmask-pro
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create
python -m venv venv

# Activate
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**
- `transformers` - DistilBERT model (~500MB download on first run)
- `torch` - ML framework
- `fastapi` - Web framework
- `pydantic` - Data validation
- `pyyaml` - Config parsing
- `gitpython` - Git operations
- `redis` - Caching (optional for demo)

**First run will download DistilBERT (~5 min on first use, then cached)**

### Step 4: Run Full Test

```bash
python run_full_test.py
```

**What happens:**
1. Creates temporary directory with sample SSIS files
2. Scans files with Regex + Context + DistilBERT
3. Tests DBA approval workflow
4. Tests rehydration engine
5. Prints results and metrics

**Expected output:**
```
🚀 LOCALMASK PRO - FULL TEST
================================================================================

PHASE 1: Detection Pipeline
🔍 Scanning...
  [1/5] Regex scan...
    Found 23 candidates
  [2-6/6] Processing with ML pipeline...
  ✓ 18 high-confidence detections

================================================================================
LOCALMASK PRO - TEST RESULTS
================================================================================

Organization: bank_hadoar
Project Type: ssis
Total Candidates: 23
High Confidence Detections: 18

DETECTIONS:
...
(Shows each detection with confidence, risk level, context)
...

RISK DISTRIBUTION: HIGH=15, MEDIUM=2, LOW=1
Average Confidence: 93%

✅ Test complete!
```

### Step 5: Verify Everything Works

Check for:
- ✅ No errors (only messages starting with ✓ or ✅)
- ✅ 15+ detections found
- ✅ Average confidence > 85%
- ✅ "Test complete!" at the end

## Detailed Breakdown of Test Phases

### Phase 1: Detection

```
Files created:
  - source_to_mrr.sql (SQL with credentials)
  - config.yaml (YAML with passwords)
  - load_ssis.py (Python with API keys)
  - .env (environment variables)
  - README.md (examples)

Detection:
  [Regex] 23 candidates found
    ↓
  [Context] Entity type + usage classified
    ↓
  [DistilBERT] Confidence scored
    ↓
  [Org Rules] Bank HaDoar rules applied
    ↓
  [Final] 18 high-confidence detections

Results:
  - prod_db_banking (server) → HIGH 94%
  - P@ssw0rd_2024! (password) → HIGH 97%
  - sk_live_abc123 (API key) → HIGH 92%
  ... (15 more)
```

### Phase 2: Learning

```
Store detections in Redis-like storage:
  - Entity: prod_db_banking
  - Token: ~[server_1]~
  - Status: user_confirmed
  - Confirmations: 1

Log teaching actions:
  - Action: "confirm"
  - Entity: "prod_db_banking"
  - Timestamp: 2024-11-20T...
```

### Phase 3: DBA Approval

```
Create approval request:
  - Scan ID: scan_001
  - Status: pending
  - DBA Email: dba@bank.com

DBA approves:
  - Status: approved
  - Approved By: dba@bank.com
  - Timestamp: 2024-11-20T...
```

### Phase 4: Rehydration

```
Masked answer from Claude:
  "ALTER TABLE ~[table_1]~ ADD Column FROM ~[server_1]~"

Rehydrate using token mapping:
  ~[table_1]~ → dbo.FactCustomers
  ~[server_1]~ → prod_db_banking

Real answer:
  "ALTER TABLE dbo.FactCustomers ADD Column FROM prod_db_banking"
```

## Manual Testing

### Test Detection Only

```python
from detectors.detector_pipeline import DetectorPipeline

pipeline = DetectorPipeline(org_id="bank_hadoar")
results = pipeline.scan_repo("/path/to/your/repo", project_type="ssis")

for detection in results["detections"]:
    print(f"{detection['entity']} - {detection['final_risk']} ({detection['final_confidence']:.0%})")
```

### Test Rehydration

```python
from engines.rehydration_engine import RehydrationEngine
from storage.redis_org_store import RedisOrgStore

store = RedisOrgStore()
store.cache_rehydration_map("bank_hadoar", "test", {
    "~[server_1]~": "prod_db_banking",
    "~[password_1]~": "secret123"
})

engine = RehydrationEngine("bank_hadoar", "test", store)
result = engine.rehydrate_answer("Connect to ~[server_1]~ with pwd=~[password_1]~")
print(result["rehydrated"])
```

### Test Organization Learning

```python
from storage.redis_org_store import RedisOrgStore

store = RedisOrgStore()
store.store_masking("bank_hadoar", "prod_db_banking", "~[server_1]~")
store.log_teaching("bank_hadoar", "confirm", "prod_db_banking")

log = store.get_learning_log("bank_hadoar")
print(log)
```

## Understanding Error Messages

### "ModuleNotFoundError"

```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

### "torch not found"

```bash
# Solution: Install PyTorch separately
pip install torch torchvision torchaudio
```

### "DistilBERT model not found"

First run downloads the model (~500MB). This is normal.
Subsequent runs use cached model.

### Memory issues

DistilBERT uses CPU by default. No GPU needed.
If still memory-constrained:
- Close other applications
- Run on machine with ≥4GB RAM

## What Each File Does

| File | Purpose |
|------|---------|
| `regex_rules_safe.py` | Defines patterns for each file type |
| `context_classifier.py` | Determines how entity is used (connection string, literal, etc) |
| `sensitivity_classifier.py` | DistilBERT model that scores sensitivity |
| `detector_pipeline.py` | Connects all components |
| `redis_org_store.py` | Stores detections and learning data |
| `rehydration_engine.py` | Converts masked → real values |
| `test_runner.py` | Runs tests and prints results |
| `run_full_test.py` | Main entry point |

## Next Steps After Successful Test

### 1. Test with Real Repository

```python
from detectors.detector_pipeline import DetectorPipeline

pipeline = DetectorPipeline(org_id="bank_hadoar")
results = pipeline.scan_repo("/path/to/real/repo", project_type="ssis")

print(f"Found {len(results['detections'])} sensitive items")
```

### 2. Customize Organization Rules

Edit `detectors/org_rules.py`:

```python
RULES = {
    "my_company": {
        ("server_name", "connection_string", "any"): "HIGH",
        ("api_key", "env_variable", "any"): "HIGH",
    }
}
```

### 3. Add Regex Patterns

Edit `detectors/regex_rules_safe.py` to add patterns for your file types.

### 4. Start Learning Loop

```python
store.store_masking(org_id, entity, token)
store.log_teaching(org_id, "confirm", entity)
# After 50 examples, model improves
```

### 5. Deploy API Server

```bash
python -m uvicorn gateway.server:app --port 8000
```

## Performance Benchmarks

| Task | Time |
|------|------|
| Scan 1 file | ~100ms |
| Scan 10 files | ~1s |
| Scan 100 files | ~50s |
| DistilBERT inference | ~45ms |
| Rehydration | ~10ms |
| Full test pipeline | ~5s |

## Troubleshooting Checklist

- [ ] Python 3.8+ installed: `python --version`
- [ ] Dependencies installed: `pip list | grep torch`
- [ ] DistilBERT downloaded: First run takes 5 min
- [ ] Test runs without errors: `python run_full_test.py`
- [ ] 18+ detections found
- [ ] Average confidence > 85%

## Getting Help

1. **Read the error message** - Usually tells you what's wrong
2. **Check console output** - Look for ✓ or ✅ signs
3. **Review README.md** - Overview of components
4. **Inspect code comments** - Each file has explanations

---

**Everything working? Congratulations! 🎉**

Next: Read `README.md` for customization options.
