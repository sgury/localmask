# Publishing this repo (one-time, ~2 minutes)

This directory is a ready-to-push git repository for the open-source free edition.
It's already committed locally. You just need to create the GitHub repo and push.

## 1. Create the empty GitHub repo

Either on github.com (New repository → name `localmask`, public, **don't** add a
README/license — this repo already has them), or with the CLI:

```bash
gh repo create localmask --public --source=. --remote=origin --push
```

If you use `gh repo create` as above, you're done — it creates and pushes.

## 2. Or push manually

```bash
git remote add origin https://github.com/<you>/localmask.git
git branch -M main
git push -u origin main
```

## 3. (Optional) publish to PyPI so `pip install localmask` works

```bash
python -m pip install build twine
python -m build              # creates dist/*.whl and *.tar.gz
python -m twine upload dist/*     # needs a PyPI account + API token
```

## What NOT to commit here

The `.gitignore` already excludes local state (`feedback_data.jsonl`, the salt,
the cache). Never add license keys, real secrets, or the Pro source
(`sensitivity_classifier.py`, `server.py`, `ui.html`, `localmask/proxy.py`,
`localmask/askai.py`) — they're intentionally not in this repo.
