# Project Conventions (copy from master, edit per project)
Agents read this before planning and building. Anything decided here is not re-asked in /grill-me.
Lines marked EDIT are placeholders, not decisions. Fill them in yourself or let the Planner ask.
Where this file differs from a global file such as ~/.gemini/GEMINI.md, this file wins for this project.

## Stack
- Language / runtime: Python 3.11+
- UI (if any): CLI + standalone static HTML report
- Data store: Immutable JSON snapshot files on disk (no database)
- Package manager: uv with pyproject.toml
- Dependencies: standard library first; ask before adding any new package.
- Linter: ruff (run: ruff check .)

## Layout
- `src/` application code; `tests/` tests; `.plans/` specs; `.env.example` lists variables with no values.

## Config & secrets
- Settings from environment variables or a `.env` file that is git-ignored. Never hardcode keys. Never print or log them.

## Logging & errors
- stdlib `logging` to a file with timestamp, level, traceback. No silent `except: pass`.
- Fail loudly with a clear message when input data is missing or malformed.

## Windows
- `pathlib` for all paths; no hardcoded absolute paths; PowerShell commands; quote paths with spaces.

## Data safety
- Tests use fixtures or temp copies. Never write to or delete the user's real data files in tests.

## Done means
- Validator PASS, README updated if CLI args / env vars / setup changed, no secrets in the diff.
