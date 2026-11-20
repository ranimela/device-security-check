"""Self-contained offline HTML report generator."""

from __future__ import annotations

import html
import json
from pathlib import Path

from device_scan.models import AnalysisResult, DeviceSnapshot, Finding


def _esc(value: object) -> str:
    """Escape text for safe HTML interpolation."""
    return html.escape(str(value), quote=True)


def _render_finding_row(finding: Finding) -> str:
    """Render a single Finding as an escaped HTML table row."""
    evidence_str = json.dumps(finding.evidence, indent=2, ensure_ascii=False)
    sev = _esc(finding.severity)
    dom = _esc(finding.domain)
    return (
        f'<tr class="finding-row" data-severity="{sev}" data-domain="{dom}">'
        f'<td><span class="badge sev-{sev}">{sev.upper()}</span></td>'
        f"<td><code>{dom}</code></td>"
        f"<td><strong>{_esc(finding.target_id)}</strong><br>"
        f'<small class="muted">{_esc(finding.check_id)}</small></td>'
        f"<td><div><strong>{_esc(finding.title)}</strong></div>"
        f'<details><summary>Evidence</summary><pre>{_esc(evidence_str)}</pre></details></td>'
        f"<td>{_esc(finding.remediation)}</td>"
        "</tr>"
    )


def render_html_report(snapshot: DeviceSnapshot, analysis: AnalysisResult) -> str:
    """Render a standalone, 100% offline HTML report from immutable contracts."""
    dev = snapshot.device
    counts = analysis.severity_counts
    is_partial = snapshot.completeness != "complete"

    completeness_banner = ""
    if is_partial:
        err_items = "".join(
            f"<li><code>{_esc(e.stage)}</code> ({_esc(e.target)}): {_esc(e.error)}</li>"
            for e in snapshot.collection_errors
        )
        completeness_banner = (
            '<div class="banner banner-warn">'
            "<strong>PARTIAL SCAN:</strong> Some device checks or packages failed to collect."
            f"<ul>{err_items}</ul>"
            "</div>"
        )
    else:
        completeness_banner = (
            '<div class="banner banner-ok">'
            "<strong>COMPLETE SCAN:</strong> All posture and package queries succeeded."
            "</div>"
        )

    multi_user_banner = ""
    if len(snapshot.users) > 1:
        user_list = ", ".join(f"{_esc(u.name)} (id={u.user_id})" for u in snapshot.users)
        multi_user_banner = (
            '<div class="banner banner-alert">'
            f"<strong>MULTI-USER ALERT:</strong> {len(snapshot.users)} user profiles detected: "
            f"{user_list}"
            "</div>"
        )

    rows_html = "\n".join(_render_finding_row(f) for f in analysis.findings)
    if not rows_html:
        rows_html = (
            '<tr><td colspan="5" class="empty-state">'
            "No security findings detected for this snapshot."
            "</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Android Security Scan — {_esc(dev.model)}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --surface: #1e293b;
      --border: #334155;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #38bdf8;
      --info: #94a3b8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.5;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ margin: 0 0 4px 0; font-size: 1.6rem; }}
    .muted {{ color: var(--muted); }}
    .meta-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px; margin: 16px 0;
    }}
    .card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 12px 16px;
    }}
    .card .label {{ font-size: 0.78rem; color: var(--muted); text-transform: uppercase; }}
    .card .val {{ font-size: 1.05rem; font-weight: 600; margin-top: 4px; }}
    .banner {{
      padding: 12px 16px; border-radius: 8px; margin: 12px 0; border: 1px solid;
    }}
    .banner-ok {{ background: #052e16; border-color: #16a34a; color: #bbf7d0; }}
    .banner-warn {{ background: #451a03; border-color: #d97706; color: #fde68a; }}
    .banner-alert {{ background: #450a0a; border-color: #dc2626; color: #fecaca; }}
    .summary-bar {{
      display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0; align-items: center;
    }}
    .filter-btn {{
      background: var(--surface); color: var(--text); border: 1px solid var(--border);
      border-radius: 6px; padding: 8px 12px; cursor: pointer; font-weight: 600;
    }}
    .filter-btn.active {{ outline: 2px solid #38bdf8; }}
    .search-box {{
      margin-left: auto; background: var(--surface); color: var(--text);
      border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; min-width: 220px;
    }}
    table {{
      width: 100%; border-collapse: collapse; background: var(--surface);
      border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
    }}
    th, td {{
      text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border);
      vertical-align: top; font-size: 0.92rem;
    }}
    th {{ background: #0b1220; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }}
    .badge {{
      display: inline-block; padding: 2px 8px; border-radius: 999px;
      font-size: 0.75rem; font-weight: 700; color: #0f172a;
    }}
    .sev-critical {{ background: var(--crit); color: #fff; }}
    .sev-high {{ background: var(--high); }}
    .sev-medium {{ background: var(--med); }}
    .sev-low {{ background: var(--low); }}
    .sev-info {{ background: var(--info); }}
    pre {{
      background: #0b1220; padding: 8px; border-radius: 6px; overflow-x: auto;
      font-size: 0.8rem; margin: 6px 0 0 0;
    }}
    summary {{ cursor: pointer; color: #38bdf8; font-size: 0.85rem; margin-top: 4px; }}
    .empty-state {{ text-align: center; padding: 24px; color: var(--muted); }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Android Security Scan Report</h1>
    <div class="muted">
      Scan ID: <code>{_esc(snapshot.scan_id)}</code> &bull;
      Captured: {_esc(snapshot.captured_at)} &bull;
      Analyzer v{_esc(analysis.analyzer_version)}
    </div>

    {completeness_banner}
    {multi_user_banner}

    <div class="meta-grid">
      <div class="card">
        <div class="label">Device</div>
        <div class="val">{_esc(dev.manufacturer)} {_esc(dev.model)}</div>
      </div>
      <div class="card">
        <div class="label">Android / SDK</div>
        <div class="val">Android {_esc(dev.android_version)} (SDK {_esc(dev.sdk_int)})</div>
      </div>
      <div class="card">
        <div class="label">Security Patch</div>
        <div class="val">{_esc(dev.security_patch_level or "unknown")}</div>
      </div>
      <div class="card">
        <div class="label">Boot / Lock</div>
        <div class="val">
          Boot: {_esc(dev.verified_boot_state)} / Locked: {_esc(dev.bootloader_locked)}
        </div>
      </div>
      <div class="card">
        <div class="label">Packages Inspected</div>
        <div class="val">{len(snapshot.packages)}</div>
      </div>
    </div>

    <div class="summary-bar">
      <button class="filter-btn active" data-sev="all">
        All ({len(analysis.findings)})
      </button>
      <button class="filter-btn" data-sev="critical">Critical ({counts.critical})</button>
      <button class="filter-btn" data-sev="high">High ({counts.high})</button>
      <button class="filter-btn" data-sev="medium">Medium ({counts.medium})</button>
      <button class="filter-btn" data-sev="low">Low ({counts.low})</button>
      <button class="filter-btn" data-sev="info">Info ({counts.info})</button>
      <input id="searchInput" class="search-box" type="search" placeholder="Filter findings...">
    </div>

    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Domain</th>
          <th>Target / Check</th>
          <th>Finding &amp; Evidence</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody id="findingsBody">
        {rows_html}
      </tbody>
    </table>
  </div>

  <script>
    (function () {{
      var activeSev = "all";
      var buttons = document.querySelectorAll(".filter-btn");
      var search = document.getElementById("searchInput");
      var rows = document.querySelectorAll(".finding-row");

      function applyFilters() {{
        var q = (search.value || "").toLowerCase();
        rows.forEach(function (row) {{
          var sev = row.getAttribute("data-severity");
          var text = row.textContent.toLowerCase();
          var sevOk = activeSev === "all" || sev === activeSev;
          var textOk = !q || text.indexOf(q) !== -1;
          row.style.display = (sevOk && textOk) ? "" : "none";
        }});
      }}

      buttons.forEach(function (btn) {{
        btn.addEventListener("click", function () {{
          buttons.forEach(function (b) {{ b.classList.remove("active"); }});
          btn.classList.add("active");
          activeSev = btn.getAttribute("data-sev");
          applyFilters();
        }});
      }});
      search.addEventListener("input", applyFilters);
    }})();
  </script>
</body>
</html>
"""


def write_html_report(
    snapshot: DeviceSnapshot,
    analysis: AnalysisResult,
    output_path: Path,
) -> Path:
    """Write the standalone HTML report to disk using UTF-8 encoding."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html_text = render_html_report(snapshot, analysis)
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write(html_text)
    return output_path
