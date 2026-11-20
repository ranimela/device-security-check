"""ADB subprocess transport and device discovery for Windows hosts."""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("device_scan.ingestion.adb_client")

DEFAULT_TIMEOUT_SECONDS = 10.0


class AdbError(RuntimeError):
    """Base exception for ADB transport and discovery failures."""


class AdbNotFoundError(AdbError):
    """Raised when ``adb`` is not found on the system PATH."""


class NoDeviceError(AdbError):
    """Raised when no Android device is attached."""


class MultipleDevicesError(AdbError):
    """Raised when multiple devices are attached and ``--serial`` is not specified."""


class DeviceUnavailableError(AdbError):
    """Raised when the selected device is unauthorized, offline, or missing."""


class AdbTimeoutError(AdbError):
    """Raised when an ADB command exceeds its timeout."""


class AdbCommandError(AdbError):
    """Raised when an ADB command exits with a non-zero status."""


@dataclass(frozen=True)
class ConnectedDevice:
    """Represents a device entry reported by ``adb devices``."""

    serial: str
    state: str


def hash_serial(serial: str) -> str:
    """Return a short deterministic SHA-256 prefix for a device serial."""
    digest = hashlib.sha256(serial.encode("utf-8")).hexdigest()
    return digest[:16]


def parse_adb_devices(output: str) -> list[ConnectedDevice]:
    """Parse ``adb devices`` stdout into a list of ConnectedDevice records.

    Args:
        output: Raw stdout from ``adb devices``.

    Returns:
        List of parsed ConnectedDevice instances.
    """
    devices: list[ConnectedDevice] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of devices attached") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append(ConnectedDevice(serial=parts[0], state=parts[1]))
    return devices


class AdbClient:
    """Minimal, timeout-bounded wrapper around the ``adb`` CLI."""

    def __init__(
        self,
        adb_path: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the ADB client.

        Args:
            adb_path: Explicit path to ``adb`` executable, or ``None`` to resolve on PATH.
            timeout_seconds: Default per-command timeout in seconds.
        """
        resolved = adb_path if adb_path is not None else shutil.which("adb")
        if not resolved:
            raise AdbNotFoundError(
                "ADB ('adb') was not found on PATH. Install Android Platform-Tools "
                "and add it to your Windows PATH before running a scan."
            )
        self._adb_path = resolved
        self._timeout_seconds = timeout_seconds

    @property
    def adb_path(self) -> str:
        """Return the resolved path to the ``adb`` executable."""
        return self._adb_path

    def _run(self, args: list[str], timeout_seconds: float | None = None) -> str:
        """Execute an ADB command and return decoded stdout."""
        effective_timeout = (
            timeout_seconds if timeout_seconds is not None else self._timeout_seconds
        )
        cmd = [self._adb_path, *args]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            logger.warning("ADB command timed out after %.1fs: %s", effective_timeout, args)
            raise AdbTimeoutError(
                f"ADB command timed out after {effective_timeout:.1f}s."
            ) from exc
        except OSError as exc:
            logger.exception("Failed to execute ADB binary.")
            raise AdbCommandError(f"Failed to execute ADB: {exc}") from exc

        if proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip()
            logger.warning("ADB exited with code %d: %s", proc.returncode, stderr)
            raise AdbCommandError(
                f"ADB exited with code {proc.returncode}: {stderr}"
            )
        return proc.stdout

    def list_devices(self) -> list[ConnectedDevice]:
        """Return all devices currently visible to ``adb devices``."""
        output = self._run(["devices"])
        return parse_adb_devices(output)

    def resolve_device(self, serial: str | None = None) -> ConnectedDevice:
        """Select and validate a single authorized target device.

        Args:
            serial: Optional explicit device serial.

        Returns:
            The selected ConnectedDevice in ``device`` state.
        """
        devices = self.list_devices()
        if not devices:
            raise NoDeviceError(
                "No Android devices detected. Connect your phone via USB, enable "
                "USB Debugging, and authorize this computer."
            )

        if serial is not None:
            matches = [d for d in devices if d.serial == serial]
            if not matches:
                raise DeviceUnavailableError(
                    f"Requested device '{hash_serial(serial)}' was not found in 'adb devices'."
                )
            target = matches[0]
        else:
            if len(devices) > 1:
                raise MultipleDevicesError(
                    f"Multiple devices detected ({len(devices)}). "
                    "Specify a single device with --serial."
                )
            target = devices[0]

        if target.state != "device":
            raise DeviceUnavailableError(
                f"Device '{hash_serial(target.serial)}' is in state '{target.state}'. "
                "Unlock the phone and accept the USB Debugging authorization prompt."
            )

        logger.info("Resolved target device %s", hash_serial(target.serial))
        return target

    def shell(
        self,
        serial: str,
        command: str,
        timeout_seconds: float | None = None,
    ) -> str:
        """Run a shell command on the target Android device."""
        return self._run(
            ["-s", serial, "shell", command],
            timeout_seconds=timeout_seconds,
        )
