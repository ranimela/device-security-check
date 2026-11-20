# Android Security Scanner (`device-scan`)

A 100% offline Windows CLI security posture and app-privilege auditor for non-rooted Android (Samsung One UI) devices over ADB.

## Prerequisites
- **Python 3.11+**
- **`uv`** (`https://docs.astral.sh/uv/`)
- **Android Platform-Tools (`adb`)** installed and available on your Windows `PATH`
- **USB Debugging** enabled on the Android device (disable it again after scanning)

## Setup
```powershell
uv sync
```

## Usage

### Run a Live Device Scan
Connect your phone via USB, unlock it, and accept the USB Debugging prompt:
```powershell
uv run device-scan scan --out .\reports
```

Optional flags:
- `--serial <id>`: Required when multiple devices/emulators are attached.
- `--include-system`: Include preinstalled system packages in addition to user-installed apps.
- `--package <name>`: Inspect a single package only.
- `--timeout <seconds>`: Per-command ADB timeout (default: `10.0`).

### Re-Analyze an Existing Snapshot Offline
No phone connection required:
```powershell
uv run device-scan analyze .\reports\snapshots\snapshot_<scan_id>.json --out .\reports
```

## Development & Tests
```powershell
uv run ruff check .
uv run pytest
```
