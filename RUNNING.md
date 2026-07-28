# ⚡ Quick Start - Run in 5 Minutes

## Option A: macOS/Linux

```bash
# 1. Navigate to project
cd localmask-pro

# 2. Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run test
python run_full_test.py

# 5. Watch results
# (Takes ~5 minutes on first run, then faster)
```

## Option B: Windows

```cmd
# 1. Navigate to project
cd localmask-pro

# 2. Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run test
python run_full_test.py

# 5. Watch results
```

## Option C: No Virtual Environment

```bash
cd localmask-pro
pip install -r requirements.txt
python run_full_test.py
```

## What You Should See

```
🚀 LOCALMASK PRO - FULL TEST
================================================================================

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

1. prod_db_banking
   Type: server_name | Risk: HIGH
   Confidence: 94%
   Context: server='prod_db_banking'

2. P@ssw0rd_MRR_2024!
   Type: password | Risk: HIGH
   Confidence: 97%
   Context: password="P@ssw0rd_MRR_2024!"

... (16 more detections)

RISK DISTRIBUTION: HIGH=15, MEDIUM=2, LOW=1
Average Confidence: 93%

✅ Test complete!
```

## If Something Goes Wrong

### Error: "No module named 'transformers'"

```bash
pip install -r requirements.txt
```

### Error: "Torch not found"

```bash
pip install torch
```

### Slow first run?

Normal! First run downloads DistilBERT (~500MB).
Subsequent runs are fast.

### No internet?

DistilBERT needs internet to download. After first download, you can work offline.

## Next Steps

✅ Test passes? Great!

→ Read `README.md` for full documentation
→ Read `SETUP.md` for detailed setup guide
→ Try with your own repository: Edit `test_runner.py` with your path

## File Overview

```
localmask-pro/
├── detectors/          ← Detection logic
├── storage/            ← Data storage
├── engines/            ← Rehydration
├── tests/              ← Test helpers
├── run_full_test.py    ← Main test ← RUN THIS
├── README.md           ← Full docs
├── SETUP.md            ← Detailed setup
└── RUNNING.md          ← This file
```

## One-Liner Test (Copy & Paste)

```bash
cd localmask-pro && pip install -r requirements.txt && python run_full_test.py
```

---

**That's it! You're done.** 🎉
