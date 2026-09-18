"""Unit tests for the detection rules -- synthetic conn records, no live
network processes required, so these run in CI."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.engine import DetectionEngine  # noqa: E402

ZONES = {
    "hosts": {
        "10.0.0.10": {"zone": "ot-engineering", "name": "eng-ws"},
        "10.0.0.30": {"zone": "it-enterprise", "name": "corp-laptop"},
    },
    "allowed_cross_zone": {
        "scada": ["ot-engineering"],
    },
}


def make_record(**overrides):
    base = {
        "ts": 1000.0,
        "src_ip": "10.0.0.30",
        "dst_ip": "127.0.0.1",
        "dst_port": 6502,
        "zone": "scada",
        "service": "turbine-plc",
        "connected": True,
        "modbus_function_code": None,
        "modbus_function_name": None,
    }
    base.update(overrides)
    return base


def test_cross_zone_violation_fires_for_disallowed_source():
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([make_record(src_ip="10.0.0.30")])
    rules = {a.rule for a in alerts}
    assert "cross_zone_violation" in rules


def test_cross_zone_violation_does_not_fire_for_allowed_source():
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([make_record(src_ip="10.0.0.10")])
    rules = {a.rule for a in alerts}
    assert "cross_zone_violation" not in rules


def test_port_scan_discovery_needs_threshold_distinct_targets():
    engine = DetectionEngine(ZONES)
    records = [
        make_record(src_ip="10.0.0.30", dst_port=6500 + i, ts=1000.0 + i * 0.1)
        for i in range(4)
    ]
    alerts = engine.process_batch(records)
    assert not any(a.rule == "port_scan_discovery" for a in alerts), "should not fire below threshold"

    records.append(make_record(src_ip="10.0.0.30", dst_port=6510, ts=1000.5))
    alerts = engine.process_batch([records[-1]])
    # the earlier 4 touches are still in this engine instance's rolling state
    assert any(a.rule == "port_scan_discovery" for a in alerts), "should fire at threshold"


def test_unexpected_modbus_write_fires_on_write_function_code():
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([
        make_record(src_ip="10.0.0.10", modbus_function_code=6, modbus_function_name="Write Single Register")
    ])
    assert any(a.rule == "unexpected_modbus_write" for a in alerts)


def test_unexpected_modbus_write_does_not_fire_on_read():
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([
        make_record(src_ip="10.0.0.10", modbus_function_code=3, modbus_function_name="Read Holding Registers")
    ])
    assert not any(a.rule == "unexpected_modbus_write" for a in alerts)


def test_repeat_offender_score_increases_with_prior_alerts():
    engine = DetectionEngine(ZONES)
    scores = []
    for i in range(3):
        alerts = engine.process_batch([make_record(src_ip="10.0.0.30", ts=1000.0 + i)])
        scores.append(next(a.score for a in alerts if a.rule == "cross_zone_violation"))
    assert scores == sorted(scores), f"scores should be non-decreasing as the source repeats offenses: {scores}"
