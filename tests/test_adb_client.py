"""Unit tests for ADB transport and device discovery."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from device_scan.ingestion.adb_client import (
    AdbClient,
    AdbCommandError,
    AdbNotFoundError,
    AdbTimeoutError,
    DeviceUnavailableError,
    MultipleDevicesError,
    NoDeviceError,
    hash_serial,
    parse_adb_devices,
)


def test_adb_missing_on_path_raises() -> None:
    """AdbClient fails loudly when adb is not on PATH."""
    with patch("device_scan.ingestion.adb_client.shutil.which", return_value=None):
        with pytest.raises(AdbNotFoundError, match="not found on PATH"):
            AdbClient()


def test_parse_adb_devices() -> None:
    """parse_adb_devices extracts serials and states while skipping headers."""
    sample = (
        "* daemon not running; starting now at tcp:5037\n"
        "* daemon started successfully\n"
        "List of devices attached\n"
        "R5CT1234567\tdevice\n"
        "emulator-5554\tunauthorized\n"
        "\n"
    )
    devices = parse_adb_devices(sample)
    assert len(devices) == 2
    assert devices[0].serial == "R5CT1234567"
    assert devices[0].state == "device"
    assert devices[1].serial == "emulator-5554"
    assert devices[1].state == "unauthorized"


def test_resolve_device_no_devices() -> None:
    """resolve_device raises NoDeviceError when no devices are attached."""
    client = AdbClient(adb_path="adb")
    proc = MagicMock(returncode=0, stdout="List of devices attached\n\n", stderr="")
    with patch("device_scan.ingestion.adb_client.subprocess.run", return_value=proc):
        with pytest.raises(NoDeviceError):
            client.resolve_device()


def test_resolve_device_multiple_without_serial() -> None:
    """resolve_device enforces --serial when multiple devices are connected."""
    client = AdbClient(adb_path="adb")
    stdout = "List of devices attached\nAAA\tdevice\nBBB\tdevice\n"
    proc = MagicMock(returncode=0, stdout=stdout, stderr="")
    with patch("device_scan.ingestion.adb_client.subprocess.run", return_value=proc):
        with pytest.raises(MultipleDevicesError, match="--serial"):
            client.resolve_device()


def test_resolve_device_multiple_with_serial() -> None:
    """resolve_device selects the matching device when --serial is given."""
    client = AdbClient(adb_path="adb")
    stdout = "List of devices attached\nAAA\tdevice\nBBB\tdevice\n"
    proc = MagicMock(returncode=0, stdout=stdout, stderr="")
    with patch("device_scan.ingestion.adb_client.subprocess.run", return_value=proc):
        selected = client.resolve_device(serial="BBB")
    assert selected.serial == "BBB"
    assert selected.state == "device"


def test_resolve_device_unauthorized() -> None:
    """resolve_device fails clearly on unauthorized devices."""
    client = AdbClient(adb_path="adb")
    stdout = "List of devices attached\nAAA\tunauthorized\n"
    proc = MagicMock(returncode=0, stdout=stdout, stderr="")
    with patch("device_scan.ingestion.adb_client.subprocess.run", return_value=proc):
        with pytest.raises(DeviceUnavailableError, match="unauthorized"):
            client.resolve_device()


def test_shell_timeout_raises_adb_timeout_error() -> None:
    """AdbClient.shell raises AdbTimeoutError on subprocess timeout."""
    client = AdbClient(adb_path="adb", timeout_seconds=1.5)
    with patch(
        "device_scan.ingestion.adb_client.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["adb"], timeout=1.5),
    ):
        with pytest.raises(AdbTimeoutError, match="timed out"):
            client.shell("AAA", "dumpsys package")


def test_shell_nonzero_exit_raises_command_error() -> None:
    """AdbClient.shell raises AdbCommandError on non-zero returncode."""
    client = AdbClient(adb_path="adb")
    proc = MagicMock(returncode=1, stdout="", stderr="error: device offline")
    with patch("device_scan.ingestion.adb_client.subprocess.run", return_value=proc):
        with pytest.raises(AdbCommandError, match="device offline"):
            client.shell("AAA", "getprop")


def test_hash_serial_deterministic_and_redacted() -> None:
    """hash_serial produces a 16-char hex digest that does not leak the raw serial."""
    raw = "R5CT1234567"
    hashed = hash_serial(raw)
    assert len(hashed) == 16
    assert raw not in hashed
    assert hashed == hash_serial(raw)
