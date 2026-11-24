# Repository Guidelines

## Project Structure & Module Organization

- `app/` contains the FastAPI application. Routes live in `app/main.py`; SSH collection, parsing, scoring, persistence, and exports are under `app/services/` and `app/reports/`.
- `aynuomodules/` contains the shared CLI audit, CVE, data, and reporting engines.
- `aynuo.py` is the CLI entry point. Keep CLI and dashboard behavior aligned by reusing shared services rather than duplicating logic.
- `frontend/` contains the framework-free HTML, CSS, JavaScript, and favicon assets.
- `tests/` contains pytest suites; reusable RouterOS exports belong in `tests/fixtures/`.
- `data/` is runtime state (SQLite, logs, enrolled public host keys). Do not commit generated data or secrets.

## Build, Test, and Development Commands

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
.\run.ps1
.\.venv\Scripts\python.exe .\aynuo.py --help
```

`run.ps1` installs runtime dependencies, starts Uvicorn on localhost, and opens the dashboard. Run a focused test with `python -m pytest tests/test_live.py -q`. Validate frontend syntax with `node --check frontend/js/app.js` when Node.js is available.

## Coding Style & Naming Conventions

Use Python 3.11+, four-space indentation, type hints on public interfaces, `snake_case` for functions/modules, and `PascalCase` for classes. Keep FastAPI handlers thin and business logic in services. JavaScript uses `camelCase`; CSS classes use kebab-case. No formatter is configured, so follow nearby style and avoid unrelated reformatting.

## Testing Guidelines

Use pytest. Name files `test_<area>.py` and tests `test_<behavior>`. Mock SSH and NVD responses in automated tests; never require a real router. Cover success, validation, credential redaction, component failure isolation, and report exports. Browser tests use Playwright and require `AYNUO_E2E_URL`.

## Commit & Pull Request Guidelines

This checkout has no Git history. Use concise Conventional Commit subjects, such as `fix(scan): isolate CVE failures`. Pull requests should explain behavior changes, list executed tests, link issues, and include dashboard screenshots for UI work. Keep changes focused and call out security or compatibility implications.

## Security & Configuration

Live access is SSH-only and read-only. Never log or persist passwords, accept unknown host keys silently, add RouterOS mutation commands, or reintroduce API/API-SSL. Preserve localhost binding, target-network validation, timeouts, and secret redaction.

