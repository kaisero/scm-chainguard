---
name: commit
description: Run linting, formatting, and tests, then commit if everything passes. Use instead of manual git commit.
allowed-tools: Bash, Read, Edit, Glob, Grep
user-invocable: true
---

# Commit

Run the GitLab CI checks locally, then commit all staged and unstaged changes if everything passes.

## Steps

Execute these checks **in order**, stopping on the first failure:

### 1. Ruff Lint Check
```bash
ruff check src/ tests/
```
If errors are found, fix them with `ruff check --fix src/ tests/` and verify the fixes are correct.

### 2. Ruff Format Check
```bash
ruff format --check src/ tests/
```
If files need reformatting, run `ruff format src/ tests/` to fix them.

### 3. Pytest
```bash
python -m pytest --tb=short -q
```
This runs the full test suite with coverage enforcement (85% minimum, configured in pyproject.toml).

### 4. Commit

If all checks pass:

1. Run `git status` and `git diff --stat` to see what changed.
2. Run `git log --oneline -5` to match the repo's commit message style.
3. Stage all relevant changes (prefer specific files over `git add -A`).
4. Draft a concise commit message summarizing the "why" of the changes.
5. Create the commit with the Co-Authored-By trailer:
```
Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

## On Failure

- **Lint errors**: Auto-fix with `ruff check --fix`, then review the changes to ensure correctness.
- **Format errors**: Auto-fix with `ruff format`, these are always safe.
- **Test failures**: Read the failure output, diagnose, and fix the code. Re-run only the failing test to iterate quickly: `python -m pytest tests/test_file.py::TestClass::test_name -v`
- **Do NOT commit** if any check fails. Report what failed and what was fixed, then re-run all checks.

## On Success

Report: checks passed, test count/coverage, and the commit hash.
