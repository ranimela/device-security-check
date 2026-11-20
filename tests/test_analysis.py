"""Unit tests for the offline security analysis engine."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from device_scan.analysis.engine import analyze_snapshot
from device_scan.models import (
    AnalysisResult,
    DeviceInfo,
    DeviceSnapshot,
    PackageRecord,
    PostureSignals,
    UserCaCert,
    UserProfile,
)


def _baseline_snapshot() -> DeviceSnapshot:
    return DeviceSnapshot(
        schema_version="1.0",
        scan_id="scan-123",
        captured_at="2026-11-20T12:00:00Z",
        completeness="complete",
        device=DeviceInfo(
            serial_hash="abc123",
            model="SM-S928B",
            manufacturer="samsung",
            android_version="14",
            sdk_int=34,
            security_patch_level="2026-10-01",
            verified_boot_state="green",
            bootloader_locked="true",
        ),
        posture=PostureSignals(
            adb_enabled=False,
            developer_options_enabled=False,
            play_protect_enabled="true",
            screen_lock_enabled="true",
            encryption_state="encrypted",
        ),
        users=(UserProfile(user_id=0, name="Owner", flags="4c13", running=True),),
        packages=(),
    )


def test_clean_baseline_has_zero_findings() -> None:
    """A hardened single-user device with no risky apps emits zero findings."""
    snapshot = _baseline_snapshot()
    result, _ = analyze_snapshot(snapshot, reference_date=date(2026, 11, 20))
    assert len(result.findings) == 0
    assert result.severity_counts.critical == 0
    assert result.severity_counts.high == 0


def test_multi_user_and_posture_risks_detected() -> None:
    """Secondary user profiles, unlocked bootloader, CA certs, and ADB are flagged."""
    base = _baseline_snapshot()
    snapshot = DeviceSnapshot(
        schema_version=base.schema_version,
        scan_id=base.scan_id,
        captured_at=base.captured_at,
        completeness="complete",
        device=DeviceInfo(
            serial_hash="abc123",
            model="SM-S928B",
            manufacturer="samsung",
            android_version="14",
            sdk_int=34,
            security_patch_level="2025-12-01",
            verified_boot_state="orange",
            bootloader_locked="false",
        ),
        posture=PostureSignals(
            adb_enabled=True,
            developer_options_enabled=True,
            play_protect_enabled="false",
            screen_lock_enabled="true",
            encryption_state="encrypted",
            user_ca_certs=(UserCaCert(alias="9a5ba575.0", subject="user-added:9a5ba575.0"),),
            http_proxy="10.0.0.2:8080",
        ),
        users=(
            UserProfile(user_id=0, name="Owner", flags="4c13", running=True),
            UserProfile(user_id=150, name="Secure Folder", flags="4001030", running=True),
        ),
        packages=(),
    )
    result, _ = analyze_snapshot(snapshot, reference_date=date(2026, 11, 20))
    check_ids = {f.check_id for f in result.findings}
    assert "MULTI_USER_DETECTED" in check_ids
    assert "POSTURE_BOOTLOADER_UNLOCKED" in check_ids
    assert "POSTURE_VERIFIED_BOOT_DEGRADED" in check_ids
    assert "POSTURE_PATCH_OUTDATED" in check_ids
    assert "POSTURE_PLAY_PROTECT_DISABLED" in check_ids
    assert "POSTURE_USER_CA_CERTS" in check_ids
    assert "POSTURE_GLOBAL_HTTP_PROXY" in check_ids
    assert "POSTURE_ADB_ENABLED" in check_ids


def test_app_sideloaded_trojan_combo_and_json_roundtrip(tmp_path: Path) -> None:
    """Sideloaded app with SMS + Accessibility + old SDK triggers critical/high findings."""
    base = _baseline_snapshot()
    risky_pkg = PackageRecord(
        package_name="com.evil.tracker",
        user_id=0,
        version_name="1.0",
        version_code=1,
        installer_package=None,
        is_system_app=False,
        target_sdk=28,
        min_sdk=21,
        first_install_at="2023-01-01 00:00:00",
        last_updated_at="2023-01-01 00:00:00",
        granted_permissions=(
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ),
        special_bindings=("accessibility_service",),
        flags=("ALLOW_BACKUP",),
    )
    trusted_pkg = PackageRecord(
        package_name="com.whatsapp",
        user_id=0,
        version_name="2.26",
        version_code=100,
        installer_package="com.android.vending",
        is_system_app=False,
        target_sdk=34,
        min_sdk=24,
        first_install_at="2026-10-01 00:00:00",
        last_updated_at="2026-11-01 00:00:00",
    )
    snapshot = DeviceSnapshot(
        schema_version=base.schema_version,
        scan_id=base.scan_id,
        captured_at=base.captured_at,
        completeness="complete",
        device=base.device,
        posture=base.posture,
        users=base.users,
        packages=(risky_pkg, trusted_pkg),
    )

    out_file = tmp_path / "analysis.json"
    result, saved = analyze_snapshot(
        snapshot,
        output_path=out_file,
        reference_date=date(2026, 11, 20),
    )
    assert saved == out_file and out_file.exists()
    reloaded = AnalysisResult.load_json(out_file)
    assert reloaded == result

    check_ids = {f.check_id for f in result.findings}
    assert "APP_TROJAN_PERMISSION_COMBO" in check_ids
    assert "APP_SIDELOADED" in check_ids
    assert "APP_HIGH_RISK_BINDING" in check_ids
    assert "APP_LOW_TARGET_SDK" in check_ids
    assert "APP_STALE_UNUPDATED" in check_ids
    assert all("com.whatsapp" not in f.target_id for f in result.findings)


def test_samsung_update_center_and_smart_switch_are_trusted() -> None:
    """Samsung Update Center and Smart Switch are not flagged as sideloaded."""
    base = _baseline_snapshot()
    samsung_pkg = PackageRecord(
        package_name="com.sec.android.app.clockpackage",
        user_id=0,
        version_name="12.6",
        version_code=126,
        installer_package="com.samsung.android.app.updatecenter",
        is_system_app=False,
        target_sdk=34,
        min_sdk=28,
        first_install_at="2026-01-01 00:00:00",
        last_updated_at="2026-10-01 00:00:00",
    )
    snapshot = DeviceSnapshot(
        schema_version=base.schema_version,
        scan_id=base.scan_id,
        captured_at=base.captured_at,
        completeness="complete",
        device=base.device,
        posture=base.posture,
        users=base.users,
        packages=(samsung_pkg,),
    )
    result, _ = analyze_snapshot(snapshot, reference_date=date(2026, 11, 20))
    assert len(result.findings) == 0
