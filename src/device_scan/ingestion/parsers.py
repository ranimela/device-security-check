"""Defensive parsers for Android / Samsung One UI ADB diagnostic outputs."""

from __future__ import annotations

import re

from device_scan.models import (
    DeviceInfo,
    PackageRecord,
    PostureSignals,
    TriStateBool,
    UserCaCert,
    UserProfile,
    VerifiedBootState,
)

_USER_RE = re.compile(r"UserInfo\{(\d+):([^:}]+):([^}]*)\}(?:\s+(running))?")
_GETPROP_RE = re.compile(r"^\[([^\]]+)\]:\s*\[(.*)\]$")
_PKG_LINE_RE = re.compile(
    r"^package:(.+?)=([a-zA-Z0-9_.-]+)\s+installer=([^\s]+)(?:\s+uid:(\d+))?"
)
_SYSTEM_PREFIXES = ("/system/", "/system_ext/", "/product/", "/vendor/", "/apex/", "/oem/")


def parse_users(output: str) -> tuple[UserProfile, ...]:
    """Parse ``pm list users`` output into UserProfile tuples."""
    users: list[UserProfile] = []
    for line in output.splitlines():
        match = _USER_RE.search(line.strip())
        if match:
            users.append(
                UserProfile(
                    user_id=int(match.group(1)),
                    name=match.group(2).strip(),
                    flags=match.group(3).strip(),
                    running=match.group(4) == "running",
                )
            )
    return tuple(users)


def parse_getprop(output: str) -> dict[str, str]:
    """Parse ``getprop`` output into a key-value dictionary."""
    props: dict[str, str] = {}
    for line in output.splitlines():
        match = _GETPROP_RE.match(line.strip())
        if match:
            props[match.group(1)] = match.group(2)
    return props


def parse_kv_settings(output: str) -> dict[str, str]:
    """Parse ``settings list <namespace>`` output into a key-value dictionary."""
    settings: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if "=" in stripped:
            key, value = stripped.split("=", 1)
            settings[key.strip()] = value.strip()
    return settings


def parse_device_info(serial_hash: str, props: dict[str, str]) -> DeviceInfo:
    """Build DeviceInfo from parsed ``getprop`` properties."""
    sdk_str = props.get("ro.build.version.sdk", "")
    sdk_int = int(sdk_str) if sdk_str.isdigit() else None

    patch = props.get("ro.build.version.security_patch") or None

    raw_boot = props.get("ro.boot.verifiedbootstate", "").strip().lower()
    verified_boot: VerifiedBootState = (
        raw_boot  # type: ignore[assignment]
        if raw_boot in {"green", "yellow", "orange", "red"}
        else "unknown"
    )

    flash_locked = props.get("ro.boot.flash.locked", "").strip()
    vbmeta_state = props.get("ro.boot.vbmeta.device_state", "").strip().lower()
    bootloader_locked: TriStateBool = "unknown"
    if flash_locked == "1" or vbmeta_state == "locked":
        bootloader_locked = "true"
    elif flash_locked == "0" or vbmeta_state == "unlocked":
        bootloader_locked = "false"

    return DeviceInfo(
        serial_hash=serial_hash,
        model=props.get("ro.product.model") or props.get("ro.product.vendor.model") or "unknown",
        manufacturer=props.get("ro.product.manufacturer") or "unknown",
        android_version=props.get("ro.build.version.release") or "unknown",
        sdk_int=sdk_int,
        security_patch_level=patch,
        verified_boot_state=verified_boot,
        bootloader_locked=bootloader_locked,
    )


def parse_component_packages(raw_value: str) -> set[str]:
    """Extract package names from colon/newline-separated ``pkg/component`` strings."""
    if not raw_value or raw_value.strip().lower() in {"null", "none"}:
        return set()
    packages: set[str] = set()
    for token in re.split(r"[:\s]+", raw_value.strip()):
        cleaned = token.strip()
        if not cleaned:
            continue
        pkg = cleaned.split("/", 1)[0].strip()
        if pkg and "." in pkg:
            packages.add(pkg)
    return packages


def parse_user_ca_certs(output: str) -> tuple[UserCaCert, ...]:
    """Parse ``ls`` output of ``/data/misc/user/0/cacerts-added``."""
    certs: list[UserCaCert] = []
    for line in output.splitlines():
        name = line.strip()
        if not name or name.startswith("total ") or "No such file" in name:
            continue
        certs.append(UserCaCert(alias=name, subject=f"user-added:{name}"))
    return tuple(certs)


def parse_active_vpn(dumpsys_connectivity: str) -> str | None:
    """Extract an active VPN package or interface indicator from ``dumpsys connectivity``."""
    for line in dumpsys_connectivity.splitlines():
        if "VPN" in line or "tun0" in line:
            pkg_match = re.search(r"([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)", line)
            if pkg_match:
                return pkg_match.group(1)
            if "CONNECTED" in line and "VPN" in line:
                return "unknown-vpn"
    return None


def parse_unknown_sources_packages(appops_output: str) -> tuple[str, ...]:
    """Extract packages with ``REQUEST_INSTALL_PACKAGES: allow`` from appops query."""
    allowed: list[str] = []
    for line in appops_output.splitlines():
        stripped = line.strip()
        if stripped and "." in stripped and not stripped.startswith("No "):
            pkg = stripped.split()[0].rstrip(":")
            if pkg not in allowed:
                allowed.append(pkg)
    return tuple(allowed)


def parse_posture_signals(
    props: dict[str, str],
    global_settings: dict[str, str],
    secure_settings: dict[str, str],
    user_ca_output: str = "",
    connectivity_output: str = "",
    unknown_sources_output: str = "",
    lock_settings_output: str = "",
) -> PostureSignals:
    """Assemble normalized PostureSignals from raw diagnostic outputs."""
    adb_enabled = global_settings.get("adb_enabled") == "1"
    dev_enabled = global_settings.get("development_settings_enabled") == "1"

    pp_raw = global_settings.get("package_verifier_user_consent")
    play_protect: TriStateBool = "unknown"
    if pp_raw is not None:
        play_protect = "false" if pp_raw.strip() == "-1" else "true"

    crypto_state = props.get("ro.crypto.state", "").strip().lower()
    encryption_state = (
        "encrypted"
        if crypto_state == "encrypted"
        else ("unencrypted" if crypto_state == "unencrypted" else "unknown")
    )

    screen_lock: TriStateBool = "unknown"
    lower_lock = lock_settings_output.lower()
    if "password" in lower_lock or "pin" in lower_lock or "pattern" in lower_lock:
        screen_lock = "true"
    elif "none" in lower_lock or "false" in lower_lock:
        screen_lock = "false"

    proxy_raw = global_settings.get("http_proxy", "").strip()
    http_proxy = proxy_raw if proxy_raw and proxy_raw != ":0" and proxy_raw != "null" else None

    return PostureSignals(
        adb_enabled=adb_enabled,
        developer_options_enabled=dev_enabled,
        play_protect_enabled=play_protect,
        screen_lock_enabled=screen_lock,
        encryption_state=encryption_state,  # type: ignore[arg-type]
        user_ca_certs=parse_user_ca_certs(user_ca_output),
        active_vpn_package=parse_active_vpn(connectivity_output),
        http_proxy=http_proxy,
        install_unknown_apps_allowed=parse_unknown_sources_packages(unknown_sources_output),
    )


def parse_pm_list_packages(output: str) -> list[tuple[str, str | None, bool]]:
    """Parse ``pm list packages -f -i -U`` into ``(package, installer, is_system)``."""
    results: list[tuple[str, str | None, bool]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("package:"):
            continue
        match = _PKG_LINE_RE.match(stripped)
        if not match:
            continue
        apk_path = match.group(1)
        package_name = match.group(2)
        installer_raw = match.group(3)
        installer = None if installer_raw == "null" else installer_raw
        is_system = apk_path.startswith(_SYSTEM_PREFIXES)
        results.append((package_name, installer, is_system))
    return results


def parse_dumpsys_package(
    package_name: str,
    user_id: int,
    output: str,
    installer_package: str | None = None,
    is_system_app: bool = False,
    special_bindings: tuple[str, ...] = (),
) -> PackageRecord:
    """Parse ``dumpsys package <pkg>`` output into a normalized PackageRecord."""
    version_name: str | None = None
    version_code: int | None = None
    target_sdk: int | None = None
    min_sdk: int | None = None
    first_install_at: str | None = None
    last_updated_at: str | None = None
    flags: list[str] = []
    granted_permissions: list[str] = []

    in_permissions_section = False
    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line.startswith("versionCode="):
            vc_match = re.search(r"versionCode=(\d+)", line)
            if vc_match:
                version_code = int(vc_match.group(1))
            min_match = re.search(r"minSdk=(\d+)", line)
            if min_match:
                min_sdk = int(min_match.group(1))
            tgt_match = re.search(r"targetSdk=(\d+)", line)
            if tgt_match:
                target_sdk = int(tgt_match.group(1))
        elif line.startswith("versionName=") and version_name is None:
            version_name = line.split("=", 1)[1].strip() or None
        elif line.startswith("installerPackageName=") and installer_package is None:
            raw_inst = line.split("=", 1)[1].strip()
            installer_package = None if raw_inst in {"", "null"} else raw_inst
        elif line.startswith("firstInstallTime=") and first_install_at is None:
            first_install_at = line.split("=", 1)[1].strip() or None
        elif line.startswith("lastUpdateTime=") and last_updated_at is None:
            last_updated_at = line.split("=", 1)[1].strip() or None
        elif line.startswith("pkgFlags=[") or line.startswith("flags=["):
            bracket_match = re.search(r"\[([^\]]*)\]", line)
            if bracket_match:
                for token in bracket_match.group(1).split():
                    if token not in flags:
                        flags.append(token)
                if "SYSTEM" in flags:
                    is_system_app = True
        elif line.startswith(("install permissions:", "runtime permissions:")):
            in_permissions_section = True
            continue
        elif in_permissions_section:
            if not line or ":" not in line and not line.startswith("android."):
                in_permissions_section = False
                continue
            if "granted=true" in line or "granted=false" not in line:
                perm = line.split(":", 1)[0].strip()
                if "." in perm and perm not in granted_permissions:
                    granted_permissions.append(perm)

    return PackageRecord(
        package_name=package_name,
        user_id=user_id,
        version_name=version_name,
        version_code=version_code,
        installer_package=installer_package,
        is_system_app=is_system_app,
        target_sdk=target_sdk,
        min_sdk=min_sdk,
        first_install_at=first_install_at,
        last_updated_at=last_updated_at,
        granted_permissions=tuple(granted_permissions),
        special_bindings=special_bindings,
        flags=tuple(flags),
        extraction_status="complete",
        extraction_error=None,
    )
