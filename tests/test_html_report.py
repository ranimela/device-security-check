"""Unit tests for the standalone offline HTML report generator."""

from __future__ import annotations

from pathlib import Path

from device_scan.models import (
    AnalysisResult,
    CollectionError,
    DeviceInfo,
    DeviceSnapshot,
    Finding,
    PostureSignals,
    SeverityCounts,
    UserProfile,
)
from device_scan.presentation.html_report import render_html_report, write_html_report


def _sample_snapshot(partial: bool = False) -> DeviceSnapshot:
    errors = (
        (CollectionError(stage="package_dumpsys", target="com.slow", error="timed out"),)
        if partial
        else ()
    )
    return DeviceSnapshot(
        schema_version="1.0",
        scan_id="scan-xyz",
        captured_at="2026-11-20T12:00:00Z",
        completeness="partial" if partial else "complete",
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
            adb_enabled=True,
            developer_options_enabled=True,
            play_protect_enabled="true",
            screen_lock_enabled="true",
            encryption_state="encrypted",
        ),
        users=(
            UserProfile(user_id=0, name="Owner", flags="4c13", running=True),
            UserProfile(user_id=150, name="Secure Folder", flags="4001030", running=True),
        ),
        collection_errors=errors,
    )


def test_render_html_report_escapes_xss_and_has_no_external_urls() -> None:
    """HTML report escapes untrusted strings and contains zero external URLs."""
    snapshot = _sample_snapshot(partial=True)
    analysis = AnalysisResult(
        schema_version="1.0",
        scan_id="scan-xyz",
        evaluated_at="2026-11-20T12:00:05Z",
        analyzer_version="0.1.0",
        severity_counts=SeverityCounts(critical=1, high=0, medium=0, low=0, info=0),
        findings=(
            Finding(
                finding_id="f-1",
                domain="installed_app",
                target_id="<script>alert(1)</script>",
                check_id="APP_SIDELOADED",
                severity="critical",
                confidence="high",
                title="Malicious <img src=x onerror=alert(1)> app",
                evidence={"pkg": "<script>"},
                remediation="Uninstall",
            ),
        ),
    )

    html_out = render_html_report(snapshot, analysis)
    assert "<!DOCTYPE html>" in html_out
    assert "PARTIAL SCAN:" in html_out
    assert "MULTI-USER ALERT:" in html_out
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
    assert "http://" not in html_out
    assert "https://" not in html_out


def test_write_html_report_creates_file(tmp_path: Path) -> None:
    """write_html_report persists the HTML file cleanly."""
    snapshot = _sample_snapshot(partial=False)
    analysis = AnalysisResult(
        schema_version="1.0",
        scan_id="scan-xyz",
        evaluated_at="2026-11-20T12:00:05Z",
        analyzer_version="0.1.0",
        severity_counts=SeverityCounts(),
        findings=(),
    )
    out = tmp_path / "reports" / "report.html"
    written = write_html_report(snapshot, analysis, out)
    assert written == out
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "COMPLETE SCAN:" in content
    assert "No security findings detected" in content
