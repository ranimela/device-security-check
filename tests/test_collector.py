"""Unit tests for the sequential ADB metadata collector."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from device_scan.ingestion.adb_client import AdbTimeoutError, ConnectedDevice
from device_scan.ingestion.collector import collect_snapshot
from device_scan.models import DeviceSnapshot

FIXTURES = Path(__file__).parent / "fixtures"


def test_collect_snapshot_complete_and_persisted(tmp_path: Path) -> None:
    """collect_snapshot writes an immutable DeviceSnapshot JSON when commands succeed."""
    adb = MagicMock()
    adb.resolve_device.return_value = ConnectedDevice(serial="R5CT1234567", state="device")

    getprop_txt = (FIXTURES / "getprop_oneui.txt").read_text(encoding="utf-8")
    users_txt = (FIXTURES / "pm_list_users_multi.txt").read_text(encoding="utf-8")
    pm_txt = (
        "package:/data/app/com.example.sideloaded/base.apk=com.example.sideloaded "
        "installer=null uid:10321\n"
    )
    dump_txt = (FIXTURES / "dumpsys_package_sideloaded.txt").read_text(encoding="utf-8")

    def fake_shell(_serial: str, cmd: str) -> str:
        if cmd == "getprop":
            return getprop_txt
        if cmd == "pm list users":
            return users_txt
        if cmd == "settings list global":
            return "adb_enabled=1\n"
        if cmd == "settings list secure":
            return "enabled_accessibility_services=com.example.sideloaded/.Svc\n"
        if cmd.startswith("pm list packages"):
            return pm_txt
        if cmd == "dumpsys package com.example.sideloaded":
            return dump_txt
        return ""

    adb.shell.side_effect = fake_shell

    snapshot, saved_path = collect_snapshot(adb=adb, snapshot_dir=tmp_path)
    assert snapshot.completeness == "complete"
    assert saved_path is not None and saved_path.exists()
    reloaded = DeviceSnapshot.load_json(saved_path)
    assert reloaded == snapshot
    assert len(reloaded.users) == 2
    assert len(reloaded.packages) == 1
    assert "accessibility_service" in reloaded.packages[0].special_bindings


def test_collect_snapshot_partial_on_package_timeout(tmp_path: Path) -> None:
    """collect_snapshot marks completeness='partial' and continues if one package times out."""
    adb = MagicMock()
    adb.resolve_device.return_value = ConnectedDevice(serial="R5CT1234567", state="device")

    pm_txt = (
        "package:/data/app/com.good/base.apk=com.good installer=com.android.vending uid:10001\n"
        "package:/data/app/com.slow/base.apk=com.slow installer=null uid:10002\n"
    )

    def fake_shell(_serial: str, cmd: str) -> str:
        if cmd.startswith("pm list packages"):
            return pm_txt
        if cmd == "dumpsys package com.slow":
            raise AdbTimeoutError("ADB command timed out after 10.0s.")
        if cmd == "dumpsys package com.good":
            return "versionCode=10 minSdk=24 targetSdk=34\nversionName=1.0\n"
        return ""

    adb.shell.side_effect = fake_shell

    snapshot, saved_path = collect_snapshot(adb=adb, snapshot_dir=tmp_path)
    assert snapshot.completeness == "partial"
    assert len(snapshot.collection_errors) == 1
    assert snapshot.collection_errors[0].target == "com.slow"
    assert len(snapshot.packages) == 2
    assert snapshot.packages[0].extraction_status == "complete"
    assert snapshot.packages[1].extraction_status == "failed"
    assert saved_path is not None and saved_path.exists()
