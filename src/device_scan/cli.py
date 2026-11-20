"""CLI entry point for the offline Android Security Scanner."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from device_scan.analysis.engine import analyze_snapshot
from device_scan.ingestion.adb_client import AdbClient, AdbError
from device_scan.ingestion.collector import collect_snapshot
from device_scan.logging_setup import configure_logging
from device_scan.models import AnalysisResult, DeviceSnapshot
from device_scan.presentation.html_report import write_html_report

logger = logging.getLogger("device_scan.cli")


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="device-scan",
        description="100% offline security posture and app-privilege auditor over ADB.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Collect an immutable snapshot via ADB, analyze offline, and write an HTML report.",
    )
    scan_parser.add_argument("--serial", default=None, help="Target device serial.")
    scan_parser.add_argument(
        "--include-system",
        action="store_true",
        help="Include preinstalled system packages.",
    )
    scan_parser.add_argument(
        "--package",
        default=None,
        help="Scan a single package name only.",
    )
    scan_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports"),
        help="Output directory for snapshots, analysis JSON, and HTML report.",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-command ADB timeout in seconds (default: 10.0).",
    )
    scan_parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Optional log file path.",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Re-run offline analysis and HTML report generation from an existing snapshot JSON.",
    )
    analyze_parser.add_argument("snapshot", type=Path, help="Path to snapshot_<id>.json.")
    analyze_parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports"),
        help="Output directory for analysis JSON and HTML report.",
    )
    analyze_parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Optional log file path.",
    )

    return parser


def _print_summary(
    snapshot: DeviceSnapshot,
    analysis: AnalysisResult,
    report_path: Path,
) -> None:
    """Print a concise user-facing scan summary to stdout."""
    c = analysis.severity_counts
    print(f"Scan ID:      {snapshot.scan_id}")
    print(f"Device:       {snapshot.device.manufacturer} {snapshot.device.model}")
    print(f"Completeness: {snapshot.completeness.upper()}")
    print(f"Users found:  {len(snapshot.users)}")
    print(f"Packages:     {len(snapshot.packages)}")
    print(
        "Findings:     "
        f"critical={c.critical}, high={c.high}, medium={c.medium}, "
        f"low={c.low}, info={c.info}"
    )
    print(f"HTML Report:  {report_path}")


def main(argv: list[str] | None = None) -> int:
    """Run the ``device-scan`` CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(log_file=args.log_file)

    out_dir: Path = args.out
    if args.command == "scan":
        try:
            adb = AdbClient(timeout_seconds=args.timeout)
            snapshot, _ = collect_snapshot(
                adb=adb,
                serial=args.serial,
                snapshot_dir=out_dir / "snapshots",
                include_system=args.include_system,
                package_filter=args.package,
            )
        except AdbError as exc:
            logger.error("Scan aborted due to ADB error: %s", exc)
            print(f"Error: {exc}", file=sys.stderr)
            return 2

        analysis_path = out_dir / "analysis" / f"analysis_{snapshot.scan_id}.json"
        analysis, _ = analyze_snapshot(snapshot, output_path=analysis_path)
        report_path = write_html_report(
            snapshot,
            analysis,
            out_dir / f"report_{snapshot.scan_id}.html",
        )
        _print_summary(snapshot, analysis, report_path)
        return 0

    if args.command == "analyze":
        if not args.snapshot.exists():
            print(f"Error: Snapshot file not found: {args.snapshot}", file=sys.stderr)
            return 2
        try:
            snapshot = DeviceSnapshot.load_json(args.snapshot)
        except (OSError, ValueError, KeyError) as exc:
            logger.exception("Failed to load snapshot %s", args.snapshot)
            print(f"Error: Invalid snapshot file: {exc}", file=sys.stderr)
            return 2

        analysis_path = out_dir / "analysis" / f"analysis_{snapshot.scan_id}.json"
        analysis, _ = analyze_snapshot(snapshot, output_path=analysis_path)
        report_path = write_html_report(
            snapshot,
            analysis,
            out_dir / f"report_{snapshot.scan_id}.html",
        )
        _print_summary(snapshot, analysis, report_path)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
