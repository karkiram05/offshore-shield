#!/usr/bin/env python3
"""Draw docs/figures/*.png from the tables scripts/build_data.py writes.
Reads only those CSV/JSON files, so a chart can't disagree with the data.

Usage:
    python scripts/build_data.py
    python scripts/make_charts.py
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CLEAN = REPO / "data" / "clean"
PROCESSED = REPO / "data" / "processed"
FIGURES = REPO / "docs" / "figures"

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#4a3aa7"]
BLUE_LIGHT = "#cde2fb"
GOOD, CRITICAL = "#0ca30c", "#d03b3b"
SEVERITY = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219", "LOW": "#0ca30c"}


def style():
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": BASELINE, "axes.labelcolor": INK_2, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": INK_2, "axes.grid": True, "grid.color": GRID,
        "grid.linewidth": 0.8, "axes.axisbelow": True, "axes.spines.top": False,
        "axes.spines.right": False, "font.family": "DejaVu Sans", "font.size": 10,
        "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
    })


def rows(path: Path) -> list[dict]:
    with path.open() as handle:
        return list(csv.DictReader(handle))


def save(fig, name):
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / name, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote docs/figures/{name}")


def segmentation():
    cases = rows(PROCESSED / "segmentation_cases.csv")
    zones = ["scada", "auxiliary", "dmz", "ot-engineering", "it-enterprise", "vendor-remote"]
    srcs = [z for z in zones if any(c["src_zone"] == z for c in cases)]
    dsts = [z for z in zones if any(c["dst_zone"] == z for c in cases)]
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    ax.grid(False)
    for c in cases:
        x, y = dsts.index(c["dst_zone"]), srcs.index(c["src_zone"])
        allowed = c["actual_allowed"] == "1"
        ok = c["matches_policy"] == "1"
        ax.add_patch(plt.Rectangle((x + 0.04, y + 0.04), 0.92, 0.92,
                                   color=SERIES[0] if allowed else BLUE_LIGHT))
        label = ("connected" if allowed else "blocked") + ("" if ok else "\nMISMATCH")
        ax.text(x + 0.5, y + 0.5, label, ha="center", va="center", fontsize=8,
                color="#ffffff" if allowed else INK, fontweight="bold" if not ok else "normal")
    ax.set_xlim(0, len(dsts))
    ax.set_ylim(0, len(srcs))
    ax.invert_yaxis()
    ax.set_xticks([i + 0.5 for i in range(len(dsts))], dsts, rotation=20)
    ax.set_yticks([i + 0.5 for i in range(len(srcs))], srcs)
    ax.set_xlabel("Destination zone")
    ax.set_ylabel("Source zone")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    matched = sum(c["matches_policy"] == "1" for c in cases)
    ax.set_title(f"Real TCP attempts across Linux network namespaces: {matched}/{len(cases)} match policy")
    save(fig, "segmentation_matrix.png")


def prioritizer():
    sweep = rows(PROCESSED / "prioritizer_sweep.csv")
    examples = rows(PROCESSED / "prioritizer_examples.csv")
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    for i, name in enumerate(dict.fromkeys(r["profile"] for r in sweep)):
        pts = [r for r in sweep if r["profile"] == name]
        ax.plot([float(p["cvss"]) for p in pts], [float(p["operational_risk_score"]) for p in pts],
                color=SERIES[i], lw=2, label=name)
    for y, band in ((25, "MEDIUM"), (50, "HIGH"), (75, "CRITICAL")):
        ax.axhline(y, color=BASELINE, lw=1, ls="--", zorder=0)
        ax.text(0.1, y + 1.2, f"{band} from {y}", fontsize=8, color=MUTED)
    for ex in examples:
        x, y = float(ex["cvss"]), float(ex["operational_risk_score"])
        ax.scatter([x], [y], s=70, color=INK, zorder=5, edgecolor=SURFACE, linewidth=2)
        ax.annotate(f"{ex['example']}\nCVSS {x} -> {y} ({ex['operational_risk']})",
                    # Placed in empty regions of the plot, in data coordinates.
                    (x, y), xytext=(6.3, 10) if x > 8 else (0.3, 90),
                    textcoords="data", fontsize=8, color=INK_2,
                    arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.8))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 100)
    ax.set_xlabel("CVSS base score")
    ax.set_ylabel("Operational risk score (0-100)")
    ax.set_title("Same CVSS, different operational risk: exposure moves the ranking")
    ax.text(0, -0.36, "Lines: vuln/ot_prioritizer.py swept over CVSS with medium safety and availability "
            "impact. Dots: the two worked examples in docs/results.md.",
            transform=ax.transAxes, fontsize=8, color=INK_2)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.13), ncol=2, fontsize=8, frameon=False)
    save(fig, "prioritizer.png")


def setpoint_writes():
    writes = rows(PROCESSED / "setpoint_writes.csv")
    xs = list(range(1, len(writes) + 1))
    values = [int(w["value_pct"]) for w in writes]
    fig, ax = plt.subplots(figsize=(7.4, 4))
    ax.step(xs, values, where="post", color=SERIES[0], lw=2)
    for x, w in zip(xs, writes):
        unsafe = w["unsafe_setpoint_write"] == "1"
        ax.scatter([x], [int(w["value_pct"])], s=80 if unsafe else 45, zorder=5,
                   color=CRITICAL if unsafe else SERIES[0], edgecolor=SURFACE, linewidth=2)
        if unsafe:
            ax.annotate(f"+{w['delta']} in one write\nunsafe_setpoint_write (CRITICAL)",
                        (x, int(w["value_pct"])), xytext=(-175, -8), textcoords="offset points",
                        fontsize=8, color=INK_2, arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.8))
    ax.set_xticks(xs, [f"write {x}" for x in xs], fontsize=8)
    ax.set_ylim(0, 110)
    ax.set_ylabel("Curtailment setpoint (%), register 40007")
    ax.set_title("Process manipulation: ramped writes pass, the abrupt jump is flagged")
    ax.text(0, -0.2, "Every write also trips unexpected_modbus_write (writes are not expected at all); "
            "automated_collection fires on write 6.", transform=ax.transAxes, fontsize=8, color=INK_2)
    save(fig, "setpoint_writes.png")


def scenario_alerts():
    counts = rows(PROCESSED / "scenario_alert_counts.csv")
    label = {("discovery", "before_hardening"): "Discovery (loose policy)",
             ("discovery", "after_hardening"): "Discovery (hardened policy)",
             ("lateral_movement", "alerts"): "Lateral movement",
             ("process_manipulation", "alerts"): "Process manipulation"}
    # One bar per (scenario, rule): six rules is more than a categorical
    # palette can keep apart, so the rule goes in the label, not the colour.
    bars = []
    for key, name in label.items():
        for c in counts:
            if (c["scenario"], c["run"]) == key:
                bars.append((f"{name}  ·  {c['rule']}", int(c["alerts"])))
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(bars) + 1.2))
    ax.grid(axis="y", visible=False)
    ys = range(len(bars))
    ax.barh(list(ys), [n for _, n in bars], color=SERIES[0], height=0.6, edgecolor=SURFACE, linewidth=2)
    for y, (_, n) in zip(ys, bars):
        ax.text(n + 0.1, y, str(n), va="center", fontsize=9, color=INK_2)
    ax.set_yticks(list(ys), [b for b, _ in bars], fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, max(n for _, n in bars) + 1)
    ax.set_xlabel("Alerts raised on the captured traffic")
    ax.set_title("Detection engine alerts per live scenario and rule")
    save(fig, "scenario_alerts.png")


def kelmarsh():
    data = rows(CLEAN / "kelmarsh_power_clean.csv")
    report = json.loads((CLEAN / "kelmarsh_quality_report.json").read_text())
    xs = list(range(len(data)))
    mean = [float(r["power_kw"]) for r in data]
    lo = [float(r["power_min_kw"]) for r in data]
    hi = [float(r["power_max_kw"]) for r in data]
    fig, ax = plt.subplots(figsize=(7.6, 3.8))
    ax.fill_between(xs, lo, hi, color=BLUE_LIGHT, lw=0, label="min-max within each 10 min window")
    ax.plot(xs, mean, color=SERIES[0], lw=2, label="mean power")
    step = max(1, len(data) // 6)
    ax.set_xticks(xs[::step], [r["timestamp"][11:16] for r in data][::step])
    ax.set_ylabel("Active power (kW)")
    ax.set_xlabel(f"{data[0]['timestamp'][:10]}, timestamps as recorded in the source file")
    what = "full file" if report["is_full_dataset"] else f"{len(data)}-row excerpt"
    ax.set_title(f"Kelmarsh wind farm SCADA, the data the turbine simulator serves ({what})")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=2, fontsize=8, frameon=False)
    save(fig, "kelmarsh_power.png")


def main():
    style()
    segmentation()
    prioritizer()
    setpoint_writes()
    scenario_alerts()
    kelmarsh()


if __name__ == "__main__":
    main()
