"""Sequential ADB metadata collector producing immutable DeviceSnapshot JSON."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from device_scan.ingestion.adb_client import AdbClient, AdbError, hash_serial
from device_scan.ingestion.parsers import (
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
from device_scan.models import (
    CollectionError,
    Completeness,
    DeviceSnapshot,
    PackageRecord,
)

logger = logging.getLogger("device_scan.ingestion.collector")


def _safe_shell(
    adb: AdbClient,
    serial: str,
    stage: str,
    target: str,
    command: str,
    errors: list[CollectionError],
) -> str:
    """Run an ADB shell command, recording non-fatal errors without aborting."""
    try:
        return adb.shell(serial, command)
    except AdbError as exc:
        logger.warning("Collection error at %s (%s): %s", stage, target, exc)
        errors.append(CollectionError(stage=stage, target=target, error=str(exc)))
        return ""


def collect_snapshot(
    adb: AdbClient,
    serial: str | None = None,
    snapshot_dir: Path | None = None,
    include_system: bool = False,
    package_filter: str | None = None,
) -> tuple[DeviceSnapshot, Path | None]:
    """Collect an immutable DeviceSnapshot from an attached Android device.

    Args:
        adb: Initialized AdbClient instance.
        serial: Optional explicit device serial.
        snapshot_dir: Optional directory to persist the snapshot JSON file.
        include_system: Whether to include preinstalled system packages.
        package_filter: Optional single package name to inspect.

    Returns:
        Tuple of ``(DeviceSnapshot, saved_json_path_or_none)``.
    """
    device = adb.resolve_device(serial=serial)
    target_serial = device.serial
    serial_hash = hash_serial(target_serial)
    scan_id = str(uuid.uuid4())
    captured_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: list[CollectionError] = []

    props_raw = _safe_shell(adb, target_serial, "device_info", "getprop", "getprop", errors)
    props = parse_getprop(props_raw)
    device_info = parse_device_info(serial_hash, props)

    users_raw = _safe_shell(adb, target_serial, "users", "pm list users", "pm list users", errors)
    users = parse_users(users_raw)

    global_raw = _safe_shell(
        adb, target_serial, "posture", "settings_global", "settings list global", errors
    )
    secure_raw = _safe_shell(
        adb, target_serial, "posture", "settings_secure", "settings list secure", errors
    )
    ca_raw = _safe_shell(
        adb,
        target_serial,
        "posture",
        "user_ca_certs",
        "ls /data/misc/user/0/cacerts-added 2>/dev/null || true",
        errors,
    )
    conn_raw = _safe_shell(
        adb, target_serial, "posture", "connectivity", "dumpsys connectivity", errors
    )
    appops_raw = _safe_shell(
        adb,
        target_serial,
        "posture",
        "install_unknown_apps",
        "cmd appops query-op --user 0 REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true",
        errors,
    )
    lock_raw = _safe_shell(
        adb,
        target_serial,
        "posture",
        "lock_settings",
        "cmd lock_settings get-disabled 2>/dev/null || true",
        errors,
    )

    global_settings = parse_kv_settings(global_raw)
    secure_settings = parse_kv_settings(secure_raw)
    posture = parse_posture_signals(
        props=props,
        global_settings=global_settings,
        secure_settings=secure_settings,
        user_ca_output=ca_raw,
        connectivity_output=conn_raw,
        unknown_sources_output=appops_raw,
        lock_settings_output=lock_raw,
    )

    # Special OS bindings mapped by package name.
    accessibility_pkgs = parse_component_packages(
        secure_settings.get("enabled_accessibility_services", "")
    )
    notif_listener_pkgs = parse_component_packages(
        secure_settings.get("enabled_notification_listeners", "")
    )
    admin_raw = _safe_shell(
        adb,
        target_serial,
        "posture",
        "device_policy",
        "dumpsys device_policy",
        errors,
    )
    device_admin_pkgs = parse_device_admins(admin_raw)
    default_sms_pkg = secure_settings.get("sms_default_application", "").strip()

    pm_cmd = "pm list packages -f -i -U --user 0"
    if not include_system and package_filter is None:
        pm_cmd += " -3"
    pm_raw = _safe_shell(adb, target_serial, "packages", "pm_list", pm_cmd, errors)
    listed = parse_pm_list_packages(pm_raw)
    if package_filter is not None:
        listed = [item for item in listed if item[0] == package_filter]

    packages: list[PackageRecord] = []
    for pkg_name, installer, is_system in listed:
        bindings: list[str] = []
        if pkg_name in accessibility_pkgs:
            bindings.append("accessibility_service")
        if pkg_name in device_admin_pkgs:
            bindings.append("device_admin")
        if pkg_name in notif_listener_pkgs:
            bindings.append("notification_listener")
        if posture.active_vpn_package == pkg_name:
            bindings.append("vpn_service")
        if default_sms_pkg == pkg_name:
            bindings.append("default_sms")

        try:
            dump_raw = adb.shell(target_serial, f"dumpsys package {pkg_name}")
            packages.append(
                parse_dumpsys_package(
                    package_name=pkg_name,
                    user_id=0,
                    output=dump_raw,
                    installer_package=installer,
                    is_system_app=is_system,
                    special_bindings=tuple(bindings),
                )
            )
        except AdbError as exc:
            logger.warning("Failed to inspect package %s: %s", pkg_name, exc)
            errors.append(
                CollectionError(stage="package_dumpsys", target=pkg_name, error=str(exc))
            )
            packages.append(
                PackageRecord(
                    package_name=pkg_name,
                    user_id=0,
                    version_name=None,
                    version_code=None,
                    installer_package=installer,
                    is_system_app=is_system,
                    target_sdk=None,
                    min_sdk=None,
                    first_install_at=None,
                    last_updated_at=None,
                    special_bindings=tuple(bindings),
                    extraction_status="failed",
                    extraction_error=str(exc),
                )
            )

    completeness: Completeness = "partial" if errors else "complete"
    snapshot = DeviceSnapshot(
        schema_version="1.0",
        scan_id=scan_id,
        captured_at=captured_at,
        completeness=completeness,
        device=device_info,
        posture=posture,
        users=users,
        packages=tuple(packages),
        collection_errors=tuple(errors),
    )

    saved_path: Path | None = None
    if snapshot_dir is not None:
        saved_path = snapshot_dir / f"snapshot_{scan_id}.json"
        snapshot.save_json(saved_path)
        logger.info("Saved %s snapshot to %s", completeness, saved_path)

    return snapshot, saved_path
