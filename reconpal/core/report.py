"""Report generation: JSON for tooling, self-contained HTML for humans."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanResult, Severity

_SEV_COLOURS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#0891b2",
    "Informational": "#64748b",
}

_CSS = """
:root {
  --bg: #f8fafc; --card: #ffffff; --ink: #0f172a; --muted: #64748b;
  --line: #e2e8f0; --accent: #4f46e5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b1120; --card: #131c31; --ink: #e2e8f0; --muted: #94a3b8;
    --line: #1e293b; --accent: #818cf8;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.wrap { max-width: 1000px; margin: 0 auto; padding: 32px 20px 64px; }
header { border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 28px; }
h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -0.02em; }
.sub { color: var(--muted); font-size: 14px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px; margin: 24px 0 32px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 16px; }
.tile .n { font-size: 26px; font-weight: 600; line-height: 1.2; }
.tile .l { font-size: 12px; color: var(--muted); text-transform: uppercase;
  letter-spacing: 0.06em; margin-top: 2px; }
h2 { font-size: 18px; margin: 32px 0 14px; }
.finding { background: var(--card); border: 1px solid var(--line); border-left-width: 4px;
  border-radius: 8px; padding: 16px 18px; margin-bottom: 14px; }
.finding h3 { margin: 0 0 6px; font-size: 16px; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.badge { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px;
  color: #fff; text-transform: uppercase; letter-spacing: 0.04em; }
.badge.conf { background: transparent; color: var(--muted);
  border: 1px solid var(--line); }
.meta { font-size: 12px; color: var(--muted); font-family: ui-monospace, monospace;
  margin-bottom: 8px; word-break: break-all; }
p { margin: 0 0 10px; }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 6px;
  padding: 10px 12px; overflow-x: auto; font-size: 12.5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 8px 0 0; }
.fix { font-size: 13.5px; color: var(--muted); border-top: 1px dashed var(--line);
  padding-top: 9px; margin-top: 10px; }
table { width: 100%; border-collapse: collapse; font-size: 13.5px;
  background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  overflow: hidden; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--muted); }
tr:last-child td { border-bottom: none; }
.scroll { overflow-x: auto; }
footer { margin-top: 40px; padding-top: 18px; border-top: 1px solid var(--line);
  font-size: 12.5px; color: var(--muted); }
.empty { background: var(--card); border: 1px dashed var(--line); border-radius: 8px;
  padding: 24px; text-align: center; color: var(--muted); }
"""


def write_json(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.to_json(), encoding="utf-8")
    return path


def write_html(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render(result), encoding="utf-8")
    return path


def _esc(value) -> str:
    return html.escape(str(value), quote=False)


def _render(result: ScanResult) -> str:
    counts = result.counts
    highest = result.highest.value if result.highest else "None"
    tiles = "".join(
        f'<div class="tile"><div class="n" style="color:{_SEV_COLOURS[s]}">'
        f'{counts[s]}</div><div class="l">{s}</div></div>'
        for s in ("Critical", "High", "Medium", "Low", "Informational")
    )

    findings_html = []
    for f in result.sorted_findings():
        colour = _SEV_COLOURS[f.severity.value]
        evidence = ""
        if f.evidence:
            evidence = (
                "<pre>"
                + _esc(json.dumps(f.evidence, indent=2, default=str))
                + "</pre>"
            )
        refs = ""
        if f.references:
            links = " · ".join(
                f'<a href="{_esc(r)}" target="_blank" rel="noopener">{_esc(r)}</a>'
                for r in f.references
            )
            refs = f'<div class="fix">Reference: {links}</div>'
        fix = f'<div class="fix"><strong>Suggested fix.</strong> {_esc(f.remediation)}</div>' if f.remediation else ""
        findings_html.append(
            f'<div class="finding" style="border-left-color:{colour}">'
            f'<div class="badges">'
            f'<span class="badge" style="background:{colour}">{_esc(f.severity.value)}</span>'
            f'<span class="badge conf">{_esc(f.confidence.value)}</span>'
            f'<span class="badge conf">{_esc(f.module)}</span>'
            f"</div>"
            f"<h3>{_esc(f.title)}</h3>"
            f'<div class="meta">{_esc(f.target)}</div>'
            f"<p>{_esc(f.summary)}</p>"
            f"{evidence}{fix}{refs}"
            f"</div>"
        )

    if not findings_html:
        findings_html = ['<div class="empty">No findings were recorded for this target.</div>']

    asset_rows = []
    for kind in ("subdomain", "endpoint", "technology", "port"):
        for a in result.assets_of(kind):
            asset_rows.append(
                f"<tr><td>{_esc(kind)}</td><td>{_esc(a.value)}</td>"
                f"<td>{_esc(a.detail)}</td><td>{_esc(a.source)}</td></tr>"
            )
    assets_table = (
        '<div class="scroll"><table><thead><tr><th>Kind</th><th>Value</th>'
        "<th>Detail</th><th>Source</th></tr></thead><tbody>"
        + "".join(asset_rows)
        + "</tbody></table></div>"
        if asset_rows
        else '<div class="empty">No assets discovered.</div>'
    )

    errors = ""
    if result.errors:
        items = "".join(f"<li>{_esc(e)}</li>" for e in result.errors)
        errors = f"<h2>Notes and errors</h2><ul>{items}</ul>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconPal report — {_esc(result.target)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<header>
  <h1>ReconPal report</h1>
  <div class="sub">{_esc(result.target)} · started {_esc(result.started_at)}
   · {result.request_count} requests · highest severity: <strong>{_esc(highest)}</strong></div>
</header>
<div class="tiles">{tiles}</div>
<h2>Findings ({len(result.findings)})</h2>
{"".join(findings_html)}
<h2>Discovered assets ({len(result.assets)})</h2>
{assets_table}
{errors}
<footer>
  Generated by ReconPal. Findings are automated observations, not confirmed
  vulnerabilities — verify each one manually before reporting it. Modules run:
  {_esc(", ".join(result.modules_run) or "none")}.
</footer>
</div></body></html>"""
