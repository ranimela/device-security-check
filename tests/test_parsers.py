"""Unit tests for One UI / Android diagnostic output parsers."""

from __future__ import annotations

from pathlib import Path

from device_scan.ingestion.parsers import (
    parse_active_vpn,
    parse_component_packages,
    parse_device_admins,
    parse_device_info,
    parse_dumpsys_package,
    parse_getprop,
    parse_kv_settings,
    parse_pm_list_packages,
    parse_posture_signals,
    parse_users,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_getprop_and_device_info() -> None:
    """parse_device_info extracts Samsung One UI hardware, OS, and boot fields."""
    props = parse_getprop((FIXTURES / "getprop_oneui.txt").read_text(encoding="utf-8"))
    info = parse_device_info("abcd1234", props)
    assert info.model == "SM-S928B"
    assert info.manufacturer == "samsung"
    assert info.android_version == "14"
    assert info.sdk_int == 34
    assert info.security_patch_level == "2026-10-01"
    assert info.verified_boot_state == "green"
    assert info.bootloader_locked == "true"


def test_parse_users_multi() -> None:
    """parse_users detects primary and secondary One UI Secure Folder users."""
    users = parse_users((FIXTURES / "pm_list_users_multi.txt").read_text(encoding="utf-8"))
    assert len(users) == 2
    assert users[0].user_id == 0
    assert users[0].running is True
    assert users[1].user_id == 150
    assert users[1].name == "Secure Folder"


def test_parse_pm_list_packages() -> None:
    """parse_pm_list_packages distinguishes sideloaded, Play Store, and system apps."""
    pkgs = parse_pm_list_packages((FIXTURES / "pm_list_packages.txt").read_text(encoding="utf-8"))
    assert len(pkgs) == 3
    assert pkgs[0] == ("com.example.sideloaded", None, False)
    assert pkgs[1] == ("com.whatsapp", "com.android.vending", False)
    assert pkgs[2] == ("com.android.settings", None, True)


def test_parse_dumpsys_package() -> None:
    """parse_dumpsys_package extracts SDKs, flags, timestamps, and granted perms."""
    raw = (FIXTURES / "dumpsys_package_sideloaded.txt").read_text(encoding="utf-8")
    rec = parse_dumpsys_package(
        package_name="com.example.sideloaded",
        user_id=0,
        output=raw,
        installer_package=None,
        is_system_app=False,
        special_bindings=("accessibility_service",),
    )
    assert rec.version_code == 42
    assert rec.version_name == "1.2.3"
    assert rec.min_sdk == 23
    assert rec.target_sdk == 28
    assert "ALLOW_BACKUP" in rec.flags
    assert "android.permission.READ_SMS" in rec.granted_permissions
    assert "android.permission.SYSTEM_ALERT_WINDOW" in rec.granted_permissions
    assert "android.permission.CAMERA" not in rec.granted_permissions
    assert rec.special_bindings == ("accessibility_service",)


def test_parse_posture_signals_and_components() -> None:
    """parse_posture_signals captures ADB, Play Protect, CA certs, proxy, and VPN."""
    props = {"ro.crypto.state": "encrypted"}
    g_settings = parse_kv_settings(
        "adb_enabled=1\ndevelopment_settings_enabled=1\n"
        "package_verifier_user_consent=-1\nhttp_proxy=192.168.1.50:8080\n"
    )
    s_settings = parse_kv_settings(
        "enabled_accessibility_services=com.example.sideloaded/.MyService\n"
    )
    posture = parse_posture_signals(
        props=props,
        global_settings=g_settings,
        secure_settings=s_settings,
        user_ca_output="9a5ba575.0\n",
        connectivity_output="NetworkAgentInfo{VPN type=VPN package=com.wireguard.android}\n",
        unknown_sources_output="com.example.sideloaded\n",
        lock_settings_output="false\n",
    )
    assert posture.adb_enabled is True
    assert posture.screen_lock_enabled == "true"
    assert posture.play_protect_enabled == "false"
    assert posture.encryption_state == "encrypted"
    assert posture.http_proxy == "192.168.1.50:8080"
    assert posture.active_vpn_package == "com.wireguard.android"
    assert len(posture.user_ca_certs) == 1
    assert posture.install_unknown_apps_allowed == ("com.example.sideloaded",)
    assert parse_component_packages(s_settings["enabled_accessibility_services"]) == {
        "com.example.sideloaded"
    }


def test_parse_device_admins_ignores_unrelated_policy_packages() -> None:
    """parse_device_admins only extracts packages inside Enabled Device Admins."""
    sample = (
        "Current Device Policy Manager state:\n"
        "  User 0\n"
        "    Enabled Device Admins (User 0, owner=false):\n"
        "      com.example.mdm/.AdminReceiver:\n"
        "        uid=10200\n"
        "    Password Policy:\n"
        "      com.dropbox.android/something\n"
        "      com.anthropic.claude/something\n"
    )
    assert parse_device_admins(sample) == {"com.example.mdm"}


def test_parse_active_vpn_ignores_iso_timestamps() -> None:
    """parse_active_vpn does not misread ISO timestamps like 51.595Z as a package."""
    sample = "2026-11-20T13:46:51.595Z VPN state=DISCONNECTED\n"
    assert parse_active_vpn(sample) is None
