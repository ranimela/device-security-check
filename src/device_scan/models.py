"""Immutable data contracts for DeviceSnapshot and AnalysisResult."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Completeness = Literal["complete", "partial"]
TriStateBool = Literal["true", "false", "unknown"]
VerifiedBootState = Literal["green", "yellow", "orange", "red", "unknown"]
EncryptionState = Literal["encrypted", "unencrypted", "unknown"]
ExtractionStatus = Literal["complete", "partial", "failed"]
FindingDomain = Literal["device_posture", "multi_user", "installed_app"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class CollectionError:
    """Represents a non-fatal ingestion error captured during collection."""

    stage: str
    target: str
    error: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectionError:
        """Build a CollectionError from a dictionary."""
        return cls(
            stage=str(data["stage"]),
            target=str(data["target"]),
            error=str(data["error"]),
        )


@dataclass(frozen=True)
class DeviceInfo:
    """Sanitized hardware and OS identity for the scanned Android device."""

    serial_hash: str
    model: str
    manufacturer: str
    android_version: str
    sdk_int: int | None
    security_patch_level: str | None
    verified_boot_state: VerifiedBootState
    bootloader_locked: TriStateBool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceInfo:
        """Build a DeviceInfo from a dictionary."""
        sdk_raw = data.get("sdk_int")
        return cls(
            serial_hash=str(data["serial_hash"]),
            model=str(data["model"]),
            manufacturer=str(data["manufacturer"]),
            android_version=str(data["android_version"]),
            sdk_int=int(sdk_raw) if sdk_raw is not None else None,
            security_patch_level=data.get("security_patch_level"),
            verified_boot_state=data.get("verified_boot_state", "unknown"),
            bootloader_locked=data.get("bootloader_locked", "unknown"),
        )


@dataclass(frozen=True)
class UserProfile:
    """Represents an Android user profile returned by ``pm list users``."""

    user_id: int
    name: str
    flags: str
    running: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserProfile:
        """Build a UserProfile from a dictionary."""
        return cls(
            user_id=int(data["user_id"]),
            name=str(data["name"]),
            flags=str(data.get("flags", "")),
            running=bool(data.get("running", False)),
        )


@dataclass(frozen=True)
class UserCaCert:
    """Represents a user-installed CA certificate."""

    alias: str
    subject: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserCaCert:
        """Build a UserCaCert from a dictionary."""
        return cls(
            alias=str(data["alias"]),
            subject=str(data["subject"]),
        )


@dataclass(frozen=True)
class PostureSignals:
    """Normalized OS security posture signals."""

    adb_enabled: bool
    developer_options_enabled: bool
    play_protect_enabled: TriStateBool
    screen_lock_enabled: TriStateBool
    encryption_state: EncryptionState
    user_ca_certs: tuple[UserCaCert, ...] = ()
    active_vpn_package: str | None = None
    http_proxy: str | None = None
    install_unknown_apps_allowed: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PostureSignals:
        """Build PostureSignals from a dictionary."""
        certs = tuple(UserCaCert.from_dict(item) for item in data.get("user_ca_certs", []))
        unknown_apps = tuple(str(pkg) for pkg in data.get("install_unknown_apps_allowed", []))
        return cls(
            adb_enabled=bool(data.get("adb_enabled", False)),
            developer_options_enabled=bool(data.get("developer_options_enabled", False)),
            play_protect_enabled=data.get("play_protect_enabled", "unknown"),
            screen_lock_enabled=data.get("screen_lock_enabled", "unknown"),
            encryption_state=data.get("encryption_state", "unknown"),
            user_ca_certs=certs,
            active_vpn_package=data.get("active_vpn_package"),
            http_proxy=data.get("http_proxy"),
            install_unknown_apps_allowed=unknown_apps,
        )


@dataclass(frozen=True)
class PackageRecord:
    """Normalized metadata for a single installed Android package."""

    package_name: str
    user_id: int
    version_name: str | None
    version_code: int | None
    installer_package: str | None
    is_system_app: bool
    target_sdk: int | None
    min_sdk: int | None
    first_install_at: str | None
    last_updated_at: str | None
    granted_permissions: tuple[str, ...] = ()
    special_bindings: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    extraction_status: ExtractionStatus = "complete"
    extraction_error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PackageRecord:
        """Build a PackageRecord from a dictionary."""
        vcode = data.get("version_code")
        tsdk = data.get("target_sdk")
        msdk = data.get("min_sdk")
        return cls(
            package_name=str(data["package_name"]),
            user_id=int(data.get("user_id", 0)),
            version_name=data.get("version_name"),
            version_code=int(vcode) if vcode is not None else None,
            installer_package=data.get("installer_package"),
            is_system_app=bool(data.get("is_system_app", False)),
            target_sdk=int(tsdk) if tsdk is not None else None,
            min_sdk=int(msdk) if msdk is not None else None,
            first_install_at=data.get("first_install_at"),
            last_updated_at=data.get("last_updated_at"),
            granted_permissions=tuple(str(p) for p in data.get("granted_permissions", [])),
            special_bindings=tuple(str(b) for b in data.get("special_bindings", [])),
            flags=tuple(str(f) for f in data.get("flags", [])),
            extraction_status=data.get("extraction_status", "complete"),
            extraction_error=data.get("extraction_error"),
        )


@dataclass(frozen=True)
class DeviceSnapshot:
    """Contract A: Immutable point-in-time snapshot produced by Ingestion."""

    schema_version: str
    scan_id: str
    captured_at: str
    completeness: Completeness
    device: DeviceInfo
    posture: PostureSignals
    users: tuple[UserProfile, ...] = ()
    packages: tuple[PackageRecord, ...] = ()
    collection_errors: tuple[CollectionError, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot to a JSON-compatible dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize snapshot to formatted JSON."""
        return json.dumps(self.to_dict(), indent=2)

    def save_json(self, path: Path) -> None:
        """Write snapshot JSON to disk using UTF-8 encoding."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            handle.write(self.to_json())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceSnapshot:
        """Deserialize a DeviceSnapshot from a dictionary."""
        return cls(
            schema_version=str(data["schema_version"]),
            scan_id=str(data["scan_id"]),
            captured_at=str(data["captured_at"]),
            completeness=data["completeness"],
            device=DeviceInfo.from_dict(data["device"]),
            posture=PostureSignals.from_dict(data["posture"]),
            users=tuple(UserProfile.from_dict(u) for u in data.get("users", [])),
            packages=tuple(PackageRecord.from_dict(p) for p in data.get("packages", [])),
            collection_errors=tuple(
                CollectionError.from_dict(e) for e in data.get("collection_errors", [])
            ),
        )

    @classmethod
    def load_json(cls, path: Path) -> DeviceSnapshot:
        """Load and validate a DeviceSnapshot from a JSON file."""
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls.from_dict(data)


@dataclass(frozen=True)
class SeverityCounts:
    """Aggregated counts of findings per severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SeverityCounts:
        """Build SeverityCounts from a dictionary."""
        return cls(
            critical=int(data.get("critical", 0)),
            high=int(data.get("high", 0)),
            medium=int(data.get("medium", 0)),
            low=int(data.get("low", 0)),
            info=int(data.get("info", 0)),
        )


@dataclass(frozen=True)
class Finding:
    """Normalized security finding emitted by the offline Analysis layer."""

    finding_id: str
    domain: FindingDomain
    target_id: str
    check_id: str
    severity: Severity
    confidence: Confidence
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Build a Finding from a dictionary."""
        return cls(
            finding_id=str(data["finding_id"]),
            domain=data["domain"],
            target_id=str(data["target_id"]),
            check_id=str(data["check_id"]),
            severity=data["severity"],
            confidence=data["confidence"],
            title=str(data["title"]),
            evidence=dict(data.get("evidence", {})),
            remediation=str(data.get("remediation", "")),
        )


@dataclass(frozen=True)
class AnalysisResult:
    """Contract B: Immutable analysis output consumed by Presentation."""

    schema_version: str
    scan_id: str
    evaluated_at: str
    analyzer_version: str
    severity_counts: SeverityCounts
    findings: tuple[Finding, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize analysis result to a JSON-compatible dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize analysis result to formatted JSON."""
        return json.dumps(self.to_dict(), indent=2)

    def save_json(self, path: Path) -> None:
        """Write analysis result JSON to disk using UTF-8 encoding."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            handle.write(self.to_json())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisResult:
        """Deserialize an AnalysisResult from a dictionary."""
        return cls(
            schema_version=str(data["schema_version"]),
            scan_id=str(data["scan_id"]),
            evaluated_at=str(data["evaluated_at"]),
            analyzer_version=str(data["analyzer_version"]),
            severity_counts=SeverityCounts.from_dict(data["severity_counts"]),
            findings=tuple(Finding.from_dict(f) for f in data.get("findings", [])),
        )

    @classmethod
    def load_json(cls, path: Path) -> AnalysisResult:
        """Load and validate an AnalysisResult from a JSON file."""
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls.from_dict(data)
