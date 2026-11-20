# Implementation Specification: Android Security Scanner (v1)

## Summary for Approval
This builds a 100% offline Windows CLI tool (`device-scan`) that connects to a non-rooted Samsung One UI phone over ADB, captures an immutable device metadata snapshot (OS posture, user profiles, and installed app metadata—no APK pulls), runs offline security rules, and outputs a self-contained HTML report.
If the phone disconnects or a One UI `dumpsys` command stalls (10s timeout), the tool records the error, marks the scan `partial`, and still generates a report for what it collected.
No external network calls or databases are used; all decisions from the conventions gate (`Python 3.11+`, `uv`, JSON snapshot store, standalone HTML) are locked.

## Goal & Non-Goals
- **Goal:** On demand, connect a non-rooted Samsung One UI phone to a Windows laptop over ADB, run a single offline metadata-only scan, and produce a standalone HTML report covering OS posture, multi-user profile alerts, and installed app privilege risks.
- **Non-Goals:**
  - Pulling or decompiling APK binaries on the laptop (metadata-only in v1).
  - Online/cloud threat-intelligence lookups (e.g., VirusTotal API calls) — v1 is 100% offline.
  - Rooting the device or requiring root privileges.
  - Continuous background monitoring, scheduled scans, or automated remediation on the phone.
  - Scanning or redacting personal user files (photos, messages, app private data).

## Architectural Overview
The system is strictly decoupled into four isolated layers communicating only via immutable JSON files on disk:
1. **Ingestion (`src/device_scan/ingestion/`):** Wraps `adb` subprocess calls on Windows (`PATH` check, `--serial` enforcement on multi-device, 10s per-command timeout). Sequentially collects `pm list users`, `getprop`, `settings`, `dumpsys` posture signals, and `--user 0` package metadata. Writes an immutable `DeviceSnapshot` JSON file to the Data Store. Contains zero security rule logic.
2. **Data Store (`snapshots/` & `models.py`):** Immutable point-in-time `DeviceSnapshot` JSON and `AnalysisResult` JSON files on disk.
3. **Analysis (`src/device_scan/analysis/`):** Pure offline rule engine. Reads `DeviceSnapshot` JSON, evaluates posture rules, single-user assertion (`len(users) > 1` alert), and app privilege/staleness rules, and writes `AnalysisResult` JSON. Never invokes `adb`.
4. **Presentation (`src/device_scan/presentation/`):** Read-only HTML generator. Reads `DeviceSnapshot` + `AnalysisResult` and renders a single self-contained HTML file with inline CSS/JS (zero external CDN requests).

## Immutable Data Contracts

### Contract A: `DeviceSnapshot` (Ingestion → Data Store)
```json
{
  "schema_version": "1.0",
  "scan_id": "uuid4",
  "captured_at": "2026-11-20T12:00:00Z",
  "completeness": "complete | partial",
  "collection_errors": [
    { "stage": "string", "target": "string", "error": "string" }
  ],
  "device": {
    "serial_hash": "sha256-prefix",
    "model": "string",
    "manufacturer": "string",
    "android_version": "string",
    "sdk_int": 34,
    "security_patch_level": "YYYY-MM-DD | null",
    "verified_boot_state": "green | yellow | orange | red | unknown",
    "bootloader_locked": "true | false | unknown"
  },
  "users": [
    { "user_id": 0, "name": "Owner", "flags": "string", "running": true }
  ],
  "posture": {
    "adb_enabled": true,
    "developer_options_enabled": true,
    "play_protect_enabled": "true | false | unknown",
    "screen_lock_enabled": "true | false | unknown",
    "encryption_state": "encrypted | unencrypted | unknown",
    "user_ca_certs": [{ "alias": "string", "subject": "string" }],
    "active_vpn_package": "string | null",
    "http_proxy": "string | null",
    "install_unknown_apps_allowed": ["package.name"]
  },
  "packages": [
    {
      "package_name": "string",
      "user_id": 0,
      "version_name": "string",
      "version_code": 1,
      "installer_package": "string | null",
      "is_system_app": false,
      "target_sdk": 34,
      "min_sdk": 24,
      "first_install_at": "ISO-8601 | null",
      "last_updated_at": "ISO-8601 | null",
      "granted_permissions": ["android.permission.CAMERA"],
      "special_bindings": ["accessibility_service", "device_admin", "notification_listener", "vpn_service", "default_sms"],
      "flags": ["DEBUGGABLE", "ALLOW_BACKUP"],
      "extraction_status": "complete | partial | failed",
      "extraction_error": "string | null"
    }
  ]
}
```

### Contract B: `AnalysisResult` (Analysis → Data Store → Presentation)
```json
{
  "schema_version": "1.0",
  "scan_id": "uuid4",
  "evaluated_at": "2026-11-20T12:00:05Z",
  "analyzer_version": "0.1.0",
  "severity_counts": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "findings": [
    {
      "finding_id": "uuid4",
      "domain": "device_posture | multi_user | installed_app",
      "target_id": "string",
      "check_id": "string",
      "severity": "critical | high | medium | low | info",
      "confidence": "high | medium | low",
      "title": "string",
      "evidence": { "key": "value" },
      "remediation": "string"
    }
  ]
}
```

## Affected Files
- `pyproject.toml` (project metadata, Python 3.11+, `ruff` config, `device-scan` CLI entry point)
- `README.md` (setup with `uv`, ADB prerequisite, CLI usage)
- `src/device_scan/__init__.py`
- `src/device_scan/logging_setup.py`
- `src/device_scan/models.py`
- `src/device_scan/ingestion/__init__.py`
- `src/device_scan/ingestion/adb_client.py`
- `src/device_scan/ingestion/parsers.py`
- `src/device_scan/ingestion/collector.py`
- `src/device_scan/analysis/__init__.py`
- `src/device_scan/analysis/posture_checks.py`
- `src/device_scan/analysis/app_checks.py`
- `src/device_scan/analysis/engine.py`
- `src/device_scan/presentation/__init__.py`
- `src/device_scan/presentation/html_report.py`
- `src/device_scan/cli.py`
- `tests/fixtures/` (sample One UI / Android `dumpsys`, `pm`, `getprop`, `settings` text outputs)
- `tests/test_adb_client.py`
- `tests/test_parsers.py`
- `tests/test_collector.py`
- `tests/test_analysis.py`
- `tests/test_html_report.py`
- `tests/test_cli_e2e.py`

## Logging & Observability
- Use stdlib `logging` writing to a local log file (e.g. `logs/device-scan.log`) with ISO timestamp, level, module name, and full traceback on exceptions, plus concise `WARNING`/`ERROR` console output.
- No silently swallowed exceptions (`except: pass` is banned). Every failed/timed-out ADB command logs a warning and appends an entry to `collection_errors`.
- Never log raw device serial numbers in plaintext (hash serial before logging/storing) or personal app data payloads.

## Step-by-Step Micro-Tasks

1. **Task 1: Project Scaffold, Logging & Immutable Data Models** *(Serves: AC-5)*
   - Create `pyproject.toml` (`uv` compatible, stdlib-only runtime dependencies, `pytest` and `ruff` dev dependencies, `device-scan` entry point), `src/device_scan/logging_setup.py`, and `src/device_scan/models.py` implementing Contracts A & B as frozen dataclasses with JSON serialization/deserialization helpers.
2. **Task 2: ADB Transport & Device Discovery** *(Serves: AC-1, AC-2, AC-5)*
   - Implement `src/device_scan/ingestion/adb_client.py` to verify `adb` on Windows `PATH`, list connected devices, enforce `--serial` when multiple devices exist, fail clearly on `unauthorized`/`offline` devices, and run shell commands with a 10s timeout. Add `tests/test_adb_client.py`.
3. **Task 3: Ingestion Parsers & Sequential Collector** *(Serves: AC-1, AC-2, AC-3, AC-5)*
   - Implement `src/device_scan/ingestion/parsers.py` (parsing `pm list users`, `getprop`, `settings`, `dumpsys` posture signals, `pm list packages -f -i -U --user 0`, and `dumpsys package <pkg>`) and `src/device_scan/ingestion/collector.py` (sequential collection with per-package error/timeout isolation and `completeness: partial` tracking, saving `DeviceSnapshot` JSON). Add fixture files and `tests/test_parsers.py`, `tests/test_collector.py`.
4. **Task 4: Offline Analysis Engine (Posture, Multi-User & App Rules)** *(Serves: AC-1, AC-2, AC-3, AC-5)*
   - Implement `src/device_scan/analysis/posture_checks.py` (patch staleness, boot/ADB/CA certs/proxy/VPN/Play Protect + multi-user assertion), `src/device_scan/analysis/app_checks.py` (trusted store allowlist `com.android.vending` & `com.sec.android.app.samsungapps`, special bindings, dangerous permission combos, low `targetSdk`, staleness), and `src/device_scan/analysis/engine.py` producing `AnalysisResult`. Add `tests/test_analysis.py`.
5. **Task 5: Standalone Offline HTML Report Generator** *(Serves: AC-4)*
   - Implement `src/device_scan/presentation/html_report.py` to render a single self-contained HTML file (escaped HTML, inline CSS/JS for severity filtering and table sorting, zero external network assets) from `DeviceSnapshot` + `AnalysisResult`. Add `tests/test_html_report.py`.
6. **Task 6: CLI Entry Point, E2E Tests & README** *(Serves: AC-1, AC-2, AC-3, AC-4, AC-5)*
   - Implement `src/device_scan/cli.py` with `scan` (live ADB -> Snapshot -> Analysis -> HTML) and `analyze` (offline Snapshot -> Analysis -> HTML) subcommands. Add `tests/test_cli_e2e.py` with mocked ADB and update `README.md` with Windows `uv` + `adb` setup and usage.

## Acceptance Traceability
| AC ID | Micro-Task(s) | Verification Method |
|---|---|---|
| AC-1 | Task 2, Task 3, Task 4, Task 6 | `pytest` on posture parsers/rules + E2E mocked scan asserting posture findings |
| AC-2 | Task 2, Task 3, Task 4, Task 6 | `pytest` fixture with `user_id` 0 & 10 verifying high-severity multi-user alert |
| AC-3 | Task 3, Task 4, Task 6 | `pytest` fixture with sideloaded + Accessibility + SMS app verifying app findings |
| AC-4 | Task 5, Task 6 | `pytest` asserting valid self-contained HTML with no external URLs, completeness banner, and severity counts |
| AC-5 | Task 1, Task 2, Task 3, Task 4, Task 6 | `pytest` simulating `adb` missing, unauthorized device, and mid-scan timeout producing `partial` report |

## Verification Criteria
- `uv run ruff check .` passes with 0 errors.
- `uv run pytest` passes all unit and E2E tests using fixtures/temp directories (zero writes to real user data).
- Manual smoke check (optional if user connects One UI phone): `uv run device-scan scan --out ./reports` completes offline and opens a valid standalone HTML report.

## Context Pruning
By default, the Builder should read only:
1. `.plans/conventions.md`
2. `.plans/android-security-scanner.md`
3. `.plans/android-security-scanner.status.json`
