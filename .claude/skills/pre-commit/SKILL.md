---
name: pre-commit
description: Run linting (ruff check + ruff format) and tests (pytest) before committing. Use this skill before every commit to catch CI failures early.
allowed-tools: Bash, Read, Edit, Glob, Grep
user-invocable: true
---

# Pre-Commit Checks

Run the same lint and test checks as the GitLab CI pipeline before committing.

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

## On Failure

- **Lint errors**: Auto-fix with `ruff check --fix`, then review the changes to ensure correctness.
- **Format errors**: Auto-fix with `ruff format`, these are always safe.
- **Test failures**: Read the failure output, diagnose, and fix the code. Re-run only the failing test to iterate quickly: `python -m pytest tests/test_file.py::TestClass::test_name -v`

## On Success

Report a one-line summary: number of lint/format issues fixed (if any) and test count/coverage.
