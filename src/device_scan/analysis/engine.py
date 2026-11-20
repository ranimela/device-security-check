"""Offline analysis orchestrator reading DeviceSnapshot and emitting AnalysisResult."""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime
from pathlib import Path

from device_scan import __version__
from device_scan.analysis.app_checks import check_installed_apps
from device_scan.analysis.posture_checks import check_device_posture, check_multi_user
from device_scan.models import AnalysisResult, DeviceSnapshot, Finding, SeverityCounts

logger = logging.getLogger("device_scan.analysis.engine")

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def analyze_snapshot(
    snapshot: DeviceSnapshot,
    output_path: Path | None = None,
    reference_date: date | None = None,
) -> tuple[AnalysisResult, Path | None]:
    """Run all offline security rules against an immutable DeviceSnapshot.

    Args:
        snapshot: Deserialized DeviceSnapshot.
        output_path: Optional file path to persist AnalysisResult JSON.
        reference_date: Optional date override for deterministic staleness checks.

    Returns:
        Tuple of ``(AnalysisResult, saved_json_path_or_none)``.
    """
    findings: list[Finding] = []
    findings.extend(check_multi_user(snapshot))
    findings.extend(check_device_posture(snapshot, reference_date=reference_date))
    findings.extend(check_installed_apps(snapshot, reference_date=reference_date))

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.domain, f.target_id))

    counts = SeverityCounts(
        critical=sum(1 for f in findings if f.severity == "critical"),
        high=sum(1 for f in findings if f.severity == "high"),
        medium=sum(1 for f in findings if f.severity == "medium"),
        low=sum(1 for f in findings if f.severity == "low"),
        info=sum(1 for f in findings if f.severity == "info"),
    )

    result = AnalysisResult(
        schema_version="1.0",
        scan_id=snapshot.scan_id,
        evaluated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        analyzer_version=__version__,
        severity_counts=counts,
        findings=tuple(findings),
    )

    if output_path is not None:
        result.save_json(output_path)
        logger.info("Saved AnalysisResult (%d findings) to %s", len(findings), output_path)

    return result, output_path
