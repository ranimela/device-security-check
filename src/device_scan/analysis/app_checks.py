"""Offline installed-application metadata risk checks."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from device_scan.models import DeviceSnapshot, Finding, PackageRecord

TRUSTED_INSTALLERS = frozenset(
    {
        "com.android.vending",
        "com.sec.android.app.samsungapps",
        "com.samsung.android.app.updatecenter",
        "com.sec.android.easyMover",
    }
)

SENSITIVE_PERMISSIONS = frozenset(
    {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    }
)

HIGH_RISK_BINDINGS = frozenset(
    {
        "accessibility_service",
        "device_admin",
        "notification_listener",
        "default_sms",
    }
)


def _make_app_finding(
    pkg: PackageRecord,
    check_id: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: dict[str, object],
    remediation: str,
) -> Finding:
    """Construct a normalized installed_app Finding."""
    return Finding(
        finding_id=str(uuid.uuid4()),
        domain="installed_app",
        target_id=f"{pkg.package_name} (user {pkg.user_id})",
        check_id=check_id,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        title=title,
        evidence=evidence,
        remediation=remediation,
    )


def _parse_android_timestamp(ts: str | None) -> date | None:
    """Parse ``dumpsys`` timestamp (e.g. ``2024-01-15 08:30:00``) to a date."""
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts.strip()[:19], fmt).date()
        except ValueError:
            continue
    return None


def check_installed_apps(
    snapshot: DeviceSnapshot,
    reference_date: date | None = None,
) -> list[Finding]:
    """Evaluate all PackageRecords in the snapshot for privilege and hygiene risks."""
    findings: list[Finding] = []
    today = reference_date if reference_date is not None else date.today()

    for pkg in snapshot.packages:
        if pkg.extraction_status == "failed":
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_EXTRACTION_FAILED",
                    severity="info",
                    confidence="high",
                    title=f"Metadata collection failed for {pkg.package_name}",
                    evidence={"error": pkg.extraction_error or "unknown"},
                    remediation="Re-run the scan with a stable USB connection.",
                )
            )
            continue

        if "DEBUGGABLE" in pkg.flags:
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_DEBUGGABLE",
                    severity="high",
                    confidence="high",
                    title=f"{pkg.package_name} has DEBUGGABLE flag enabled",
                    evidence={"flags": list(pkg.flags)},
                    remediation="Uninstall debug builds or replace with a release build.",
                )
            )

        if pkg.is_system_app:
            continue

        is_sideloaded = pkg.installer_package not in TRUSTED_INSTALLERS
        granted_sensitive = sorted(set(pkg.granted_permissions) & SENSITIVE_PERMISSIONS)
        high_bindings = sorted(set(pkg.special_bindings) & HIGH_RISK_BINDINGS)

        has_sms_or_calls = bool(
            set(granted_sensitive)
            & {
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CALL_LOG",
            }
        )
        has_overlay_or_a11y = (
            "android.permission.SYSTEM_ALERT_WINDOW" in granted_sensitive
            or "accessibility_service" in high_bindings
        )

        if has_sms_or_calls and has_overlay_or_a11y:
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_TROJAN_PERMISSION_COMBO",
                    severity="critical",
                    confidence="high",
                    title=(
                        f"{pkg.package_name} combines SMS/call-log access with "
                        "overlay or Accessibility control"
                    ),
                    evidence={
                        "installer": pkg.installer_package,
                        "bindings": high_bindings,
                        "sensitive_permissions": granted_sensitive,
                    },
                    remediation=(
                        "Verify this app immediately. If unrecognized, revoke Accessibility/"
                        "Admin permissions and uninstall it."
                    ),
                )
            )

        if is_sideloaded:
            sev = "high" if (high_bindings or granted_sensitive) else "medium"
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_SIDELOADED",
                    severity=sev,
                    confidence="high",
                    title=f"{pkg.package_name} was installed outside official app stores",
                    evidence={
                        "installer_package": pkg.installer_package,
                        "version_name": pkg.version_name,
                    },
                    remediation=(
                        "Verify the APK source or replace with a Play Store / Galaxy Store version."
                    ),
                )
            )

        if high_bindings:
            sev = "critical" if is_sideloaded else "high"
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_HIGH_RISK_BINDING",
                    severity=sev,
                    confidence="high",
                    title=(
                        f"{pkg.package_name} holds privileged OS binding(s): "
                        f"{', '.join(high_bindings)}"
                    ),
                    evidence={"special_bindings": high_bindings},
                    remediation=(
                        "Confirm this app legitimately needs Accessibility/Admin/Notification."
                    ),
                )
            )

        if granted_sensitive and not (has_sms_or_calls and has_overlay_or_a11y):
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_SENSITIVE_PERMISSIONS",
                    severity="medium" if len(granted_sensitive) >= 3 else "low",
                    confidence="high",
                    title=(
                        f"{pkg.package_name} has {len(granted_sensitive)} sensitive "
                        "permission(s) granted"
                    ),
                    evidence={"permissions": granted_sensitive},
                    remediation=(
                        "Review and revoke unnecessary permissions in Android App Settings."
                    ),
                )
            )

        if pkg.target_sdk is not None and pkg.target_sdk < 31:
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_LOW_TARGET_SDK",
                    severity="medium",
                    confidence="high",
                    title=f"{pkg.package_name} targets outdated Android SDK {pkg.target_sdk}",
                    evidence={"target_sdk": pkg.target_sdk},
                    remediation=(
                        "Update the app or replace unmaintained apps targeting old Android APIs."
                    ),
                )
            )

        updated_date = _parse_android_timestamp(pkg.last_updated_at)
        if updated_date is not None and (today - updated_date).days > 730:
            findings.append(
                _make_app_finding(
                    pkg=pkg,
                    check_id="APP_STALE_UNUPDATED",
                    severity="low",
                    confidence="medium",
                    title=f"{pkg.package_name} has not been updated in over 2 years",
                    evidence={"last_updated_at": pkg.last_updated_at},
                    remediation="Update or uninstall abandoned applications.",
                )
            )

    return findings
