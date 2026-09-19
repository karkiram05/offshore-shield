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


ASSET_INVENTORY = "unknown"  # classify_zone()'s return for a host not in zones.json's hosts map
OT_ZONES = {"scada", "auxiliary"}  # dst zones that count as OT for the rogue-master check


def rule_rogue_master(records: list[dict], zones: dict, state: dict) -> list[Finding]:
    """A source that isn't in this lab's provisioned-host inventory
    (zones.json's `hosts` map) reaching an OT-zone service directly. In a
    real deployment this is asset-inventory drift: a device nobody
    provisioned or documented is talking to control-system infrastructure.
    Maps to ATT&CK ICS T0848 (Rogue Master) -- an unrecognized device
    sending control-protocol traffic to a PLC/RTU is exactly the pattern
    a fraudulent master exhibits before it's caught, whether or not intent
    is ever established."""
    findings = []
    for rec in records:
        dst_zone = rec.get("zone")
        if dst_zone not in OT_ZONES:
            continue
        src_zone = classify_zone(rec["src_ip"], zones)
        if src_zone != ASSET_INVENTORY:
            continue
        findings.append(Finding(
            rule="rogue_master",
            confidence=0.8,
            technique_id="T0848",
            src_ip=rec["src_ip"],
            summary=f"Unrecognized device {rec['src_ip']} (not in the provisioned-host inventory) reached {dst_zone} zone asset {rec['service']}",
            evidence={"dst_zone": dst_zone, "service": rec["service"]},
        ))
    return findings


AUTOMATED_COLLECTION_WINDOW_S = 10.0
AUTOMATED_COLLECTION_THRESHOLD = 6  # requests to the *same* (dst_ip, dst_port) in the window


def rule_automated_collection(records: list[dict], zones: dict, state: dict) -> list[Finding]:
    """Many requests from one source to the *same* destination service in a
    short window -- unlike rule_port_scan_discovery (many distinct targets,
    ATT&CK Discovery), this is repeated querying of one point, well above
    what this lab's telemetry feeder's own polling cadence would produce
    (see lab/plc_sim's --interval, default 2s). Maps to ATT&CK ICS T0802
    (Automated Collection): a script or tool polling a control point far
    faster than a human operator or the legitimate feeder would."""
    findings = []
    history = state.setdefault("repeat_touches", {})  # (src_ip,dst_ip,dst_port) -> list[ts]

    for rec in records:
        key = (rec["src_ip"], rec["dst_ip"], rec["dst_port"])
        touches = history.setdefault(key, [])
        touches.append(rec["ts"])
        cutoff = rec["ts"] - AUTOMATED_COLLECTION_WINDOW_S
        history[key] = [t for t in touches if t >= cutoff]

        if len(history[key]) >= AUTOMATED_COLLECTION_THRESHOLD:
            findings.append(Finding(
                rule="automated_collection",
                confidence=min(1.0, 0.5 + 0.05 * len(history[key])),
                technique_id="T0802",
                src_ip=rec["src_ip"],
                summary=f"{rec['src_ip']} made {len(history[key])} requests to {rec['service']} in {AUTOMATED_COLLECTION_WINDOW_S:.0f}s -- faster than this lab's own telemetry feeder polls",
                evidence={"request_count": len(history[key]), "window_s": AUTOMATED_COLLECTION_WINDOW_S, "service": rec["service"]},
            ))
            history[key] = []  # avoid re-alerting every single record in the burst
    return findings


LATERAL_MOVEMENT_WINDOW_S = 30.0


def rule_lateral_movement_pivot(records: list[dict], zones: dict, state: dict) -> list[Finding]:
    """Catches a sequence rule_cross_zone_violation can't: a host that was
    just reached as a *destination*, then shortly afterward itself
    initiates a connection onward into a *different* zone. Each individual
    hop can be perfectly allowed by the zone policy (a jump host is
    *supposed* to be reachable from IT and *supposed* to reach OT-engineering
    -- that's what makes it a jump host) -- it's the pivot pattern across
    two allowed hops, not either hop alone, that's the lateral-movement
    signal. Maps to ATT&CK ICS T0859 (Valid Accounts): using what looks
    like a legitimate session on an already-permitted path is exactly how
    real lateral movement evades allow-list-only network security."""
    findings = []
    recently_dst = state.setdefault("recently_dst", {})  # ip -> ts last seen as a destination

    for rec in records:
        recently_dst[rec["dst_ip"]] = rec["ts"]

        src = rec["src_ip"]
        last_dst_ts = recently_dst.get(src)
        if last_dst_ts is None or rec["ts"] <= last_dst_ts:
            continue
        delay = rec["ts"] - last_dst_ts
        if delay > LATERAL_MOVEMENT_WINDOW_S:
            continue

        src_zone = classify_zone(src, zones)
        dst_zone = rec.get("zone")
        if dst_zone == src_zone:
            continue  # not actually moving to a new zone

        findings.append(Finding(
            rule="lateral_movement_pivot",
            confidence=0.85,
            technique_id="T0859",
            src_ip=src,
            summary=f"{src} was reached as a destination {delay:.1f}s ago and has now pivoted onward to {dst_zone} zone asset {rec['service']} -- a two-hop pattern, not caught by either hop's own zone check",
            evidence={"pivot_delay_s": round(delay, 2), "dst_zone": dst_zone, "service": rec["service"]},
        ))
        del recently_dst[src]  # avoid re-alerting on every subsequent record from this pivot
    return findings


SETPOINT_ABRUPT_DELTA_PCT = 25  # a single write changing a 0-100 setpoint by this many points or more


def rule_unsafe_setpoint_write(records: list[dict], zones: dict, state: dict) -> list[Finding]:
    """A Modbus Write Single Register (function code 6) that changes a
    writable control setpoint (e.g. the turbine simulator's curtailment
    setpoint at holding register 40007) abruptly -- a large jump in one
    write, rather than the small ramped steps a real turbine controller's
    engineering interface would send. This is deliberately narrower and
    more specific than rule_unexpected_modbus_write, which already flags
    *any* write to a lab asset modeled as read-only: that rule catches
    "a write happened at all," this one catches "the value written is
    itself mechanically unsafe," and both are meant to co-fire on the
    same abrupt write -- overlapping detections are intentional
    defense-in-depth, not redundancy to be suppressed. Maps to ATT&CK ICS
    T0836 (Modify Parameter), the same technique as
    rule_unexpected_modbus_write, since both observe a parameter
    modification -- this rule adds the safety-impact framing STATUS.md
    calls for (an abrupt 0%->100% curtailment command risks real
    drivetrain/blade-pitch mechanical stress on an actual turbine) rather
    than treating every write as equally severe regardless of the value
    written."""
    findings = []
    last_value = state.setdefault("setpoint_last_value", {})  # (dst_ip, dst_port, register_addr) -> last written value

    for rec in records:
        if rec.get("modbus_function_code") != 6:
            continue
        addr = rec.get("modbus_write_register_addr")
        val = rec.get("modbus_write_register_value")
        if addr is None or val is None:
            continue

        key = (rec["dst_ip"], rec["dst_port"], addr)
        prev = last_value.get(key)
        last_value[key] = val
        if prev is None:
            continue  # first write we've observed to this register -- no baseline to compare against yet

        delta = abs(val - prev)
        if delta >= SETPOINT_ABRUPT_DELTA_PCT:
            findings.append(Finding(
                rule="unsafe_setpoint_write",
                confidence=0.9,
                technique_id="T0836",
                src_ip=rec["src_ip"],
                summary=(
                    f"{rec['src_ip']} wrote an abrupt {delta}-point setpoint change ({prev} -> {val}) "
                    f"to {rec['service']} register {addr} -- real turbine controllers ramp this kind of "
                    "command gradually; a jump this size risks drivetrain/blade-pitch mechanical stress"
                ),
                evidence={"register": addr, "prev_value": prev, "new_value": val, "delta": delta, "service": rec["service"]},
            ))
    return findings


ALL_RULES = [
    rule_port_scan_discovery,
    rule_cross_zone_violation,
    rule_unexpected_modbus_write,
    rule_rogue_master,
    rule_automated_collection,
    rule_lateral_movement_pivot,
    rule_unsafe_setpoint_write,
]
