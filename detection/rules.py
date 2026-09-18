"""Detection rules operating on conn.log-style records from the network tap.

Each rule is a plain function: (records, zones, state) -> list[Finding].
`state` is a small dict the engine carries between calls so rules can track
recent history (e.g. how many ports a source has touched in the last N
seconds) without re-scanning the whole log every tick.
"""
from dataclasses import dataclass, field


@dataclass
class Finding:
    rule: str
    confidence: float  # 0-1, this rule's own confidence in the finding
    technique_id: str
    src_ip: str
    summary: str
    evidence: dict = field(default_factory=dict)


PORT_SCAN_WINDOW_S = 15.0
PORT_SCAN_DISTINCT_PORT_THRESHOLD = 5


def classify_zone(ip: str, zones: dict) -> str:
    return zones.get("hosts", {}).get(ip, {}).get("zone", "unknown")


def rule_port_scan_discovery(records: list[dict], zones: dict, state: dict) -> list[Finding]:
    """Many distinct (dst_ip, dst_port) pairs from one source in a short
    window -> OT network/service discovery. Maps to ATT&CK ICS T0846
    (Remote System Discovery) and T0840 (Network Connection Enumeration)."""
    findings = []
    history = state.setdefault("touches", {})  # src_ip -> list[(ts, dst_ip, dst_port)]

    for rec in records:
        src = rec["src_ip"]
        touches = history.setdefault(src, [])
        touches.append((rec["ts"], rec["dst_ip"], rec["dst_port"]))
        # Window is relative to this record's own timestamp, not wall-clock
        # time, so this works identically for live traffic and for batch
        # replay of historical conn.log data (the scenario harness does
        # the latter).
        cutoff = rec["ts"] - PORT_SCAN_WINDOW_S
        history[src] = [t for t in touches if t[0] >= cutoff]

        distinct = {(t[1], t[2]) for t in history[src]}
        if len(distinct) >= PORT_SCAN_DISTINCT_PORT_THRESHOLD:
            findings.append(Finding(
                rule="port_scan_discovery",
                confidence=min(1.0, 0.5 + 0.05 * len(distinct)),
                technique_id="T0846",
                src_ip=src,
                summary=f"{src} touched {len(distinct)} distinct service(s) in {PORT_SCAN_WINDOW_S:.0f}s",
                evidence={"distinct_targets": len(distinct), "window_s": PORT_SCAN_WINDOW_S},
            ))
            history[src] = []  # avoid re-alerting every single record in the burst
    return findings


def rule_cross_zone_violation(records: list[dict], zones: dict, state: dict) -> list[Finding]:
    """A source whose zone isn't on the allow-list for the destination zone
    it reached. Maps to ATT&CK ICS T0886 (Remote Services)."""
    findings = []
    allowed = zones.get("allowed_cross_zone", {})
    for rec in records:
        src_zone = classify_zone(rec["src_ip"], zones)
        dst_zone = rec.get("zone")
        if dst_zone not in allowed:
            continue
        if src_zone not in allowed[dst_zone]:
            findings.append(Finding(
                rule="cross_zone_violation",
                confidence=0.9,
                technique_id="T0886",
                src_ip=rec["src_ip"],
                summary=f"{rec['src_ip']} ({src_zone}) reached {dst_zone} zone asset {rec['service']} -- not on the allow-list",
                evidence={"src_zone": src_zone, "dst_zone": dst_zone, "service": rec["service"]},
            ))
    return findings


def rule_unexpected_modbus_write(records: list[dict], zones: dict, state: dict) -> list[Finding]:
    """A write-type Modbus function code against a telemetry point this lab
    treats as read-only. Maps to ATT&CK ICS T0836 (Modify Parameter)."""
    from lab.tap.network_tap import UNEXPECTED_WRITE_CODES  # local import: lab/ isn't a dependency of detection/ elsewhere

    findings = []
    for rec in records:
        code = rec.get("modbus_function_code")
        if code in UNEXPECTED_WRITE_CODES:
            findings.append(Finding(
                rule="unexpected_modbus_write",
                confidence=0.85,
                technique_id="T0836",
                src_ip=rec["src_ip"],
                summary=f"{rec['src_ip']} sent Modbus function {code} ({rec.get('modbus_function_name')}) to {rec['service']}, a read-only point in this lab",
                evidence={"function_code": code, "service": rec["service"]},
            ))
    return findings


ALL_RULES = [
    rule_port_scan_discovery,
    rule_cross_zone_violation,
    rule_unexpected_modbus_write,
]
