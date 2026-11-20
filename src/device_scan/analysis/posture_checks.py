"""Offline OS posture and single-user assertion checks."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from device_scan.models import DeviceSnapshot, Finding


def _make_finding(
    domain: str,
    target_id: str,
    check_id: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: dict[str, object],
    remediation: str,
) -> Finding:
    """Construct a normalized Finding with a unique ID."""
    return Finding(
        finding_id=str(uuid.uuid4()),
        domain=domain,  # type: ignore[arg-type]
        target_id=target_id,
        check_id=check_id,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        title=title,
        evidence=evidence,
        remediation=remediation,
    )


def check_multi_user(snapshot: DeviceSnapshot) -> list[Finding]:
    """Assert single-user device expectation and alert on secondary profiles."""
    if len(snapshot.users) <= 1:
        return []

    secondary = [
        {"user_id": u.user_id, "name": u.name, "running": u.running}
        for u in snapshot.users
        if u.user_id != 0
    ]
    return [
        _make_finding(
            domain="multi_user",
            target_id="device.users",
            check_id="MULTI_USER_DETECTED",
            severity="high",
            confidence="high",
            title=f"Unexpected secondary Android user profile(s) detected ({len(secondary)})",
            evidence={"users": secondary, "total_users": len(snapshot.users)},
            remediation=(
                "Inspect Settings -> Accounts / Work Profile / Secure Folder / Dual Apps "
                "and remove any unrecognized user profiles."
            ),
        )
    ]


def _parse_patch_date(patch_str: str | None) -> date | None:
    """Parse ``YYYY-MM-DD`` security patch level strings."""
    if not patch_str:
        return None
    try:
        return datetime.strptime(patch_str.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def check_device_posture(
    snapshot: DeviceSnapshot,
    reference_date: date | None = None,
) -> list[Finding]:
    """Evaluate OS, boot, network, and configuration posture signals."""
    findings: list[Finding] = []
    dev = snapshot.device
    posture = snapshot.posture
    today = reference_date if reference_date is not None else date.today()

    if dev.bootloader_locked == "false":
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="device.bootloader",
                check_id="POSTURE_BOOTLOADER_UNLOCKED",
                severity="critical",
                confidence="high",
                title="Device bootloader is unlocked",
                evidence={"bootloader_locked": dev.bootloader_locked},
                remediation="Re-lock the bootloader if not intentionally running custom firmware.",
            )
        )

    if dev.verified_boot_state in {"orange", "red", "yellow"}:
        sev = "critical" if dev.verified_boot_state == "red" else "high"
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="device.verified_boot",
                check_id="POSTURE_VERIFIED_BOOT_DEGRADED",
                severity=sev,
                confidence="high",
                title=f"Verified Boot state is '{dev.verified_boot_state}' (not green)",
                evidence={"verified_boot_state": dev.verified_boot_state},
                remediation="Verify firmware integrity and ensure Verified Boot is enforcing.",
            )
        )

    patch_date = _parse_patch_date(dev.security_patch_level)
    if patch_date is None:
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="device.security_patch",
                check_id="POSTURE_PATCH_UNKNOWN",
                severity="low",
                confidence="medium",
                title="Android security patch level could not be determined",
                evidence={"security_patch_level": dev.security_patch_level},
                remediation=(
                    "Check Settings -> Software update to confirm current security patches."
                ),
            )
        )
    else:
        age_days = (today - patch_date).days
        if age_days > 180:
            findings.append(
                _make_finding(
                    domain="device_posture",
                    target_id="device.security_patch",
                    check_id="POSTURE_PATCH_OUTDATED",
                    severity="high",
                    confidence="high",
                    title=f"Android security patch is {age_days} days old",
                    evidence={
                        "security_patch_level": dev.security_patch_level,
                        "age_days": age_days,
                    },
                    remediation="Install available Samsung One UI / Android security updates.",
                )
            )
        elif age_days > 90:
            findings.append(
                _make_finding(
                    domain="device_posture",
                    target_id="device.security_patch",
                    check_id="POSTURE_PATCH_STALE",
                    severity="medium",
                    confidence="high",
                    title=f"Android security patch is {age_days} days old",
                    evidence={
                        "security_patch_level": dev.security_patch_level,
                        "age_days": age_days,
                    },
                    remediation="Check for pending Android security updates.",
                )
            )

    if posture.screen_lock_enabled == "false":
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.screen_lock",
                check_id="POSTURE_NO_SCREEN_LOCK",
                severity="critical",
                confidence="medium",
                title="Screen lock appears disabled",
                evidence={"screen_lock_enabled": posture.screen_lock_enabled},
                remediation="Enable a strong PIN, password, or biometric screen lock.",
            )
        )

    if posture.encryption_state == "unencrypted":
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.encryption",
                check_id="POSTURE_UNENCRYPTED_STORAGE",
                severity="critical",
                confidence="high",
                title="Device storage is unencrypted",
                evidence={"encryption_state": posture.encryption_state},
                remediation="Enable full-disk or file-based encryption immediately.",
            )
        )

    if posture.play_protect_enabled == "false":
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.play_protect",
                check_id="POSTURE_PLAY_PROTECT_DISABLED",
                severity="high",
                confidence="high",
                title="Google Play Protect verification is disabled",
                evidence={"play_protect_enabled": posture.play_protect_enabled},
                remediation="Enable Play Protect in Google Play Store -> Play Protect settings.",
            )
        )

    if posture.user_ca_certs:
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.user_ca_certs",
                check_id="POSTURE_USER_CA_CERTS",
                severity="high",
                confidence="high",
                title=f"User-installed CA certificate(s) detected ({len(posture.user_ca_certs)})",
                evidence={"certs": [c.alias for c in posture.user_ca_certs]},
                remediation=(
                    "Review Settings -> Security -> User credentials and remove any "
                    "unrecognized CA certificates (potential HTTPS interception vector)."
                ),
            )
        )

    if posture.http_proxy:
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.http_proxy",
                check_id="POSTURE_GLOBAL_HTTP_PROXY",
                severity="medium",
                confidence="high",
                title=f"Global HTTP proxy configured ({posture.http_proxy})",
                evidence={"http_proxy": posture.http_proxy},
                remediation="Clear global HTTP proxy settings if not intentionally configured.",
            )
        )

    if posture.active_vpn_package:
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.active_vpn",
                check_id="POSTURE_ACTIVE_VPN",
                severity="info",
                confidence="medium",
                title=f"Active VPN detected ({posture.active_vpn_package})",
                evidence={"active_vpn_package": posture.active_vpn_package},
                remediation="Confirm this VPN app is trusted and intentionally active.",
            )
        )

    if posture.install_unknown_apps_allowed:
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.install_unknown_apps",
                check_id="POSTURE_UNKNOWN_APPS_ALLOWED",
                severity="medium",
                confidence="high",
                title=(
                    "Apps allowed to install unknown packages "
                    f"({len(posture.install_unknown_apps_allowed)})"
                ),
                evidence={"packages": list(posture.install_unknown_apps_allowed)},
                remediation="Revoke 'Install unknown apps' permission from browsers/file managers.",
            )
        )

    if posture.adb_enabled:
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.adb_enabled",
                check_id="POSTURE_ADB_ENABLED",
                severity="medium",
                confidence="high",
                title="USB Debugging (ADB) is currently enabled",
                evidence={"adb_enabled": True},
                remediation=(
                    "Disable USB Debugging in Developer Options once this scan is complete."
                ),
            )
        )
    elif posture.developer_options_enabled:
        findings.append(
            _make_finding(
                domain="device_posture",
                target_id="posture.developer_options",
                check_id="POSTURE_DEV_OPTIONS_ENABLED",
                severity="low",
                confidence="high",
                title="Developer Options are enabled",
                evidence={"developer_options_enabled": True},
                remediation="Disable Developer Options when not actively needed.",
            )
        )

    return findings
