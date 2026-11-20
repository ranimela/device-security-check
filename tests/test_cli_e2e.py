"""End-to-end CLI tests for ``device-scan scan`` and ``device-scan analyze``."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from device_scan.cli import main
from device_scan.ingestion.adb_client import AdbNotFoundError, AdbTimeoutError, ConnectedDevice

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_scan_and_offline_reanalyze_e2e(tmp_path: Path) -> None:
    """CLI scan creates snapshot, analysis, and HTML report; analyze re-runs offline."""
    out_dir = tmp_path / "out"
    log_file = tmp_path / "scan.log"

    getprop_txt = (FIXTURES / "getprop_oneui.txt").read_text(encoding="utf-8")
    users_txt = (FIXTURES / "pm_list_users_multi.txt").read_text(encoding="utf-8")
    pm_txt = (FIXTURES / "pm_list_packages.txt").read_text(encoding="utf-8")
    dump_txt = (FIXTURES / "dumpsys_package_sideloaded.txt").read_text(encoding="utf-8")

    fake_adb = MagicMock()
    fake_adb.resolve_device.return_value = ConnectedDevice(serial="R5CT1234567", state="device")

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
        if cmd == "dumpsys package com.whatsapp":
            raise AdbTimeoutError("timed out")
        return ""

    fake_adb.shell.side_effect = fake_shell

    with patch("device_scan.cli.AdbClient", return_value=fake_adb):
        rc = main(["scan", "--out", str(out_dir), "--log-file", str(log_file)])

    assert rc == 0
    snapshots = list((out_dir / "snapshots").glob("snapshot_*.json"))
    analyses = list((out_dir / "analysis").glob("analysis_*.json"))
    reports = list(out_dir.glob("report_*.html"))
    assert len(snapshots) == 1
    assert len(analyses) == 1
    assert len(reports) == 1

    html_text = reports[0].read_text(encoding="utf-8")
    assert "PARTIAL SCAN:" in html_text
    assert "MULTI-USER ALERT:" in html_text
    assert "com.example.sideloaded" in html_text

    # Now re-analyze offline into a new directory without ADB.
    reanalyze_dir = tmp_path / "reanalyzed"
    rc2 = main(
        [
            "analyze",
            str(snapshots[0]),
            "--out",
            str(reanalyze_dir),
            "--log-file",
            str(log_file),
        ]
    )
    assert rc2 == 0
    assert len(list(reanalyze_dir.glob("report_*.html"))) == 1


def test_cli_scan_adb_missing_returns_nonzero(tmp_path: Path) -> None:
    """CLI scan exits cleanly with code 2 when adb is missing from PATH."""
    log_file = tmp_path / "scan.log"
    with patch(
        "device_scan.cli.AdbClient",
        side_effect=AdbNotFoundError("ADB not found on PATH"),
    ):
        rc = main(["scan", "--out", str(tmp_path / "out"), "--log-file", str(log_file)])
    assert rc == 2
