# PRD: Android Security Scanner (v1)

## Problem
The user currently performs no security checks on their personal, non-rooted Samsung One UI Android device and lacks visibility into risky OS settings, interception vectors, and over-privileged or sideloaded apps. There is no simple, offline, on-demand way to inspect device posture and installed app metadata from a Windows laptop and receive an actionable report.

## User & Job-to-be-Done
- **User:** Personal Android device owner running a Windows laptop and a non-rooted Samsung One UI phone.
- **Job-to-be-Done:** On demand, connect the phone to the laptop, run a single offline scan, and review a standalone HTML report highlighting OS posture risks, unexpected user profiles, and high-risk app privileges so the user can remediate them.

## Success Metric
- `[UNVERIFIED]` **Scan Speed:** Complete a full metadata-only scan of all installed packages and device posture settings in under 30 seconds once the device is connected.
- `[UNVERIFIED]` **Signal-to-Noise:** Produce zero parser crashes across all installed apps, and separate high-risk/actionable findings from informational baseline items so the user can review top risks in under 2 minutes.

## Non-Goals
- Pulling or decompiling APK binaries on the laptop (metadata-only in v1).
- Online/cloud threat-intelligence lookups (e.g., VirusTotal API calls) — v1 is 100% offline.
- Rooting the device or requiring root privileges.
- Continuous background monitoring, scheduled scans, or automated remediation on the phone.
- Scanning or redacting personal user files (photos, messages, app private data).

## Acceptance Criteria
- **AC-1 (Device Posture Audit):** Given a non-rooted Samsung One UI device connected to a Windows laptop with debugging enabled, when the user runs an on-demand scan, then the tool collects OS security posture signals (OS/security patch level, verified boot/bootloader state, screen lock/encryption state, Play Protect status, USB debugging/developer options state, user-installed CA certificates, active proxy/VPN) and records findings with severity and remediation steps.
- **AC-2 (Single-User Assertion & Multi-User Alert):** Given a connected Android device, when the scan enumerates device user profiles, then if more than one user profile exists (e.g., Work Profile, Secure Folder, Dual Apps, Private Space), the tool flags a high-visibility alert in the report listing the unexpected profile IDs.
- **AC-3 (Installed App Metadata Risk Audit):** Given the packages installed on the device, when the scan completes offline metadata analysis, then it flags sideloaded apps (non-official installer), apps with high-risk special bindings (Accessibility Service, Device Admin, Notification Listener, VPN, default SMS/Dialer), dangerous runtime permission combinations (e.g., SMS, call log, background location, mic/camera, overlay), and deprecated `targetSdk` or stale apps.
- **AC-4 (Standalone HTML Report):** Given a completed scan (or partial scan if the device disconnects mid-run), when the scan finishes, then a single self-contained HTML report is written to disk showing device summary, scan completeness status, severity counts, and filterable/grouped findings.
- **AC-5 (100% Offline & Safe Failure):** Given a laptop with no internet connection, when the user runs a scan, then all checks complete without network calls; if the device is unauthorized, disconnected, or a specific package query fails, the tool records the error clearly without crashing.

## Assumptions
- `[CONFIRMED]` Host OS is Windows; target device is a non-rooted Samsung One UI phone.
- `[CONFIRMED]` Connection is on-demand from the PC; v1 is metadata-only and 100% offline.
- `[CONFIRMED]` Output is a standalone HTML file for personal local consumption.
- `[UNVERIFIED]` Android debugging (ADB) is available on the Windows host and can be temporarily enabled on the phone for each scan.
- `[UNVERIFIED]` Target Samsung One UI devices run Android 12 or newer.

## Kill Criteria
- `[UNVERIFIED]` Abandon or rethink v1 if Samsung One UI diagnostic outputs vary too unpredictably to reliably extract core posture/permission signals without root, or if false-positive noise makes the HTML report unusable without manual tuning.

## Open Questions
1. Do you confirm the suggested **Success Metric** thresholds (under 30s scan time; reviewable in under 2 minutes)?
2. Do you confirm the suggested **Kill Criteria**?
3. Which specific Android / One UI version(s) are on your device(s)?
