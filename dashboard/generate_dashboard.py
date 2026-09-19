#!/usr/bin/env python3
"""Generates dashboard/index.html: a small, static, read-only view over
this repo's real output -- every scenario's scenarios/results/*.json file
and the detection rules' own source (to build the rule -> ATT&CK technique
table, parsed from detection/rules.py rather than hand-duplicated, so it
can't silently drift out of sync with the actual rule code).

STATUS.md originally described this as "today: JSON scenario output and
terminal alert stream; planned: a small read-only web view" -- this is
that planned view, kept deliberately small: a static HTML file generated
from real files on disk, not a running server with its own attack
surface, state, or dependencies. Regenerate any time with `make
dashboard` after rerunning scenarios; nothing here is hand-typed.

Usage:
    python3 dashboard/generate_dashboard.py
"""
import html
import json
import re
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "scenarios" / "results"
RULES_SOURCE = REPO_ROOT / "detection" / "rules.py"
ATTCK_SOURCE = REPO_ROOT / "detection" / "attck_ics.py"
OUT_PATH = Path(__file__).parent / "index.html"


def load_technique_names() -> dict[str, str]:
    """Parse detection/attck_ics.py's TECHNIQUES dict for id -> name,
    rather than importing it -- this script has no dependency on the
    detection package being importable from wherever it's run."""
    text = ATTCK_SOURCE.read_text()
    names = {}
    for match in re.finditer(r'"(T\d{4})":\s*\{\s*"name":\s*"([^"]+)"', text):
        names[match.group(1)] = match.group(2)
    return names


def load_rule_technique_map() -> list[dict]:
    """Parse detection/rules.py for each `def rule_...` function, its
    first docstring line, and every technique_id="T####" literal used
    inside its body -- generated from the real source, not maintained by
    hand as a separate table that could drift from the rule code."""
    text = RULES_SOURCE.read_text()
    # Split on top-level `def rule_...(` so each chunk is one rule's body
    # up to (not including) the next top-level def or ALL_RULES.
    chunks = re.split(r"\ndef (rule_\w+)\(", text)
    # chunks[0] is preamble; then alternating name, body, name, body, ...
    rules = []
    for i in range(1, len(chunks), 2):
        name = chunks[i]
        body = chunks[i + 1]
        doc_match = re.search(r'"""(.+?)(?:\n|""")', body, re.DOTALL)
        summary = doc_match.group(1).strip() if doc_match else ""
        technique_ids = sorted(set(re.findall(r'technique_id="(T\d{4})"', body)))
        rules.append({"name": name, "summary": summary, "technique_ids": technique_ids})
    return rules


def load_scenario_results() -> list[tuple[str, dict]]:
    if not RESULTS_DIR.exists():
        return []
    results = []
    for path in sorted(RESULTS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        results.append((path.stem, data))
    return results


def render_value(value) -> str:
    if isinstance(value, bool):
        cls = "flag-true" if value else "flag-false"
        return f'<span class="{cls}">{"yes" if value else "no"}</span>'
    if isinstance(value, dict):
        return render_dict(value)
    if isinstance(value, list):
        if not value:
            return "<em>none</em>"
        if all(isinstance(v, (str, int, float, bool)) for v in value):
            return ", ".join(html.escape(str(v)) for v in value)
        return "<br>".join(render_value(v) for v in value)
    if isinstance(value, float):
        return f"{value:.4g}"
    return html.escape(str(value))


def render_dict(d: dict) -> str:
    rows = []
    for key, value in d.items():
        if key in ("generated_at",):
            continue  # rendered separately as a timestamp in the card header
        label = html.escape(key.replace("_", " "))
        rows.append(f"<tr><th>{label}</th><td>{render_value(value)}</td></tr>")
    return f'<table class="kv">{"".join(rows)}</table>'


def scenario_title(stem: str) -> str:
    return stem.replace("_", " ").title()


CSS = """
:root {
  --bg: #0b0f14; --panel: #121821; --border: #24303d; --text: #d6e0ea;
  --muted: #7c8a99; --accent: #4fb3ff; --good: #3ecf8e; --bad: #ff6b6b;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  padding: 32px 20px 64px;
}
.wrap { max-width: 980px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin: 36px 0 16px; }
.subtitle { color: var(--muted); font-size: 13px; margin: 0 0 32px; }
.card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px 20px; margin-bottom: 16px;
}
.card-header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 10px; }
.card-header h3 { margin: 0; font-size: 15px; }
.card-header .ts { color: var(--muted); font-size: 12px; }
table.kv { width: 100%; border-collapse: collapse; font-size: 13px; }
table.kv th { text-align: left; color: var(--muted); font-weight: 400; padding: 4px 12px 4px 0; vertical-align: top; white-space: nowrap; }
table.kv td { padding: 4px 0; word-break: break-word; }
table.rules { width: 100%; border-collapse: collapse; font-size: 13px; }
table.rules th, table.rules td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
table.rules th { color: var(--muted); font-weight: 400; }
.technique { display: inline-block; background: #1a2432; border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; margin: 1px 3px 1px 0; font-size: 12px; }
.technique a { color: var(--accent); text-decoration: none; }
.flag-true { color: var(--good); font-weight: 600; }
.flag-false { color: var(--bad); font-weight: 600; }
.empty { color: var(--muted); font-style: italic; }
.footer { color: var(--muted); font-size: 12px; margin-top: 48px; border-top: 1px solid var(--border); padding-top: 16px; }
code { background: #1a2432; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
"""


def build_html(rules: list[dict], technique_names: dict[str, str], results: list[tuple[str, dict]]) -> str:
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    rule_rows = []
    for r in rules:
        techniques_html = "".join(
            f'<span class="technique"><a href="https://attack.mitre.org/techniques/{tid}/" target="_blank" rel="noopener">'
            f'{tid} {html.escape(technique_names.get(tid, "?"))}</a></span>'
            for tid in r["technique_ids"]
        ) or '<span class="empty">none</span>'
        rule_rows.append(
            f"<tr><td><code>{html.escape(r['name'])}</code></td>"
            f"<td>{html.escape(r['summary'])}</td>"
            f"<td>{techniques_html}</td></tr>"
        )

    result_cards = []
    if not results:
        result_cards.append(
            '<p class="empty">No scenario results found under scenarios/results/. '
            "Run <code>make demo-discovery</code>, <code>make demo-cicd</code>, "
            "<code>make demo-lateral-movement</code>, <code>make demo-process-manipulation</code>, or "
            "<code>make demo-network-segmentation</code> (each with <code>--write-results</code>), "
            "then regenerate.</p>"
        )
    for stem, data in results:
        ts = data.get("generated_at")
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if isinstance(ts, (int, float)) else ""
        body = render_dict(data) if isinstance(data, dict) else render_value(data)
        result_cards.append(
            f'<div class="card"><div class="card-header">'
            f"<h3>{html.escape(scenario_title(stem))}</h3>"
            f'<span class="ts">{ts_str}</span></div>{body}</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OffshoreShield Dashboard</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>OffshoreShield</h1>
  <p class="subtitle">Static, read-only dashboard -- generated {generated_at} from real files in this
  repo (scenarios/results/*.json and detection/rules.py). Not a running server; regenerate with
  <code>make dashboard</code> after rerunning any scenario.</p>

  <h2>Detection rules &rarr; ATT&amp;CK for ICS techniques</h2>
  <table class="rules">
    <tr><th>Rule</th><th>What it catches</th><th>Technique(s)</th></tr>
    {"".join(rule_rows)}
  </table>

  <h2>Scenario results</h2>
  {"".join(result_cards)}

  <div class="footer">
    OffshoreShield &middot; every number above came from an actual run of the corresponding
    scenario script, not from this generator &middot; see STATUS.md and docs/architecture.md
    for what's real, what's simulated, and why.
  </div>
</div>
</body>
</html>
"""


def main():
    technique_names = load_technique_names()
    rules = load_rule_technique_map()
    results = load_scenario_results()
    out = build_html(rules, technique_names, results)
    OUT_PATH.write_text(out)
    print(f"[dashboard] wrote {OUT_PATH} ({len(out)} bytes), {len(rules)} rule(s), {len(results)} scenario result file(s)")


if __name__ == "__main__":
    main()
