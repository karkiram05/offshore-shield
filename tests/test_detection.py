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


def test_rogue_master_fires_for_unrecognized_source_reaching_ot_zone():
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([make_record(src_ip="10.0.0.99")])  # not in ZONES["hosts"] at all
    assert any(a.rule == "rogue_master" for a in alerts)


def test_rogue_master_does_not_fire_for_a_provisioned_host():
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([make_record(src_ip="10.0.0.10")])  # a known, provisioned host
    assert not any(a.rule == "rogue_master" for a in alerts)


def test_automated_collection_needs_threshold_repeat_requests():
    engine = DetectionEngine(ZONES)
    records = [
        make_record(src_ip="10.0.0.10", ts=1000.0 + i * 0.5)
        for i in range(5)
    ]
    alerts = engine.process_batch(records)
    assert not any(a.rule == "automated_collection" for a in alerts), "should not fire below threshold"

    sixth = make_record(src_ip="10.0.0.10", ts=1002.6)
    alerts = engine.process_batch([sixth])
    assert any(a.rule == "automated_collection" for a in alerts), "should fire at threshold"


def test_automated_collection_does_not_fire_for_distinct_destinations():
    """Distinct destinations is rule_port_scan_discovery's job, not this one --
    automated_collection is specifically about repeated hits on the *same* point."""
    engine = DetectionEngine(ZONES)
    records = [
        make_record(src_ip="10.0.0.10", dst_port=6500 + i, ts=1000.0 + i * 0.5)
        for i in range(6)
    ]
    alerts = engine.process_batch(records)
    assert not any(a.rule == "automated_collection" for a in alerts)


def test_lateral_movement_pivot_fires_for_two_hop_pattern():
    engine = DetectionEngine(ZONES)
    # hop 1: it-enterprise host reaches a dmz service
    hop1 = make_record(src_ip="10.0.0.30", dst_ip="10.0.0.20", zone="dmz", service="jumphost-mgmt", ts=1000.0)
    # hop 2: that same dmz host (now acting as src) reaches a scada asset, 3s later
    hop2 = make_record(src_ip="10.0.0.20", dst_ip="127.0.0.1", zone="scada", service="turbine-plc", ts=1003.0)
    alerts = engine.process_batch([hop1, hop2])
    pivots = [a for a in alerts if a.rule == "lateral_movement_pivot"]
    assert len(pivots) == 1
    assert pivots[0].src_ip == "10.0.0.20"


def test_lateral_movement_pivot_does_not_fire_for_a_single_hop():
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([make_record(src_ip="10.0.0.30", ts=1000.0)])
    assert not any(a.rule == "lateral_movement_pivot" for a in alerts)


def test_lateral_movement_pivot_does_not_fire_outside_the_window():
    engine = DetectionEngine(ZONES)
    hop1 = make_record(src_ip="10.0.0.30", dst_ip="10.0.0.20", zone="dmz", service="jumphost-mgmt", ts=1000.0)
    hop2 = make_record(src_ip="10.0.0.20", dst_ip="127.0.0.1", zone="scada", service="turbine-plc", ts=1000.0 + 60.0)
    alerts = engine.process_batch([hop1, hop2])
    assert not any(a.rule == "lateral_movement_pivot" for a in alerts)


def test_repeat_offender_score_increases_with_prior_alerts():
    engine = DetectionEngine(ZONES)
    scores = []
    for i in range(3):
        alerts = engine.process_batch([make_record(src_ip="10.0.0.30", ts=1000.0 + i)])
        scores.append(next(a.score for a in alerts if a.rule == "cross_zone_violation"))
    assert scores == sorted(scores), f"scores should be non-decreasing as the source repeats offenses: {scores}"


def make_write_record(addr, value, **overrides):
    return make_record(
        modbus_function_code=6,
        modbus_function_name="Write Single Register",
        modbus_write_register_addr=addr,
        modbus_write_register_value=value,
        **overrides,
    )


def test_unsafe_setpoint_write_fires_on_abrupt_change():
    engine = DetectionEngine(ZONES)
    baseline = make_write_record(6, 0, ts=1000.0)  # establishes the setpoint's starting value, 0%
    abrupt = make_write_record(6, 100, ts=1001.0)  # 0% -> 100% in one write
    alerts = engine.process_batch([baseline, abrupt])
    unsafe = [a for a in alerts if a.rule == "unsafe_setpoint_write"]
    assert len(unsafe) == 1
    assert unsafe[0].evidence["delta"] == 100


def test_unsafe_setpoint_write_does_not_fire_on_first_observed_write():
    # No baseline yet for this register -- nothing to compare the first write against.
    engine = DetectionEngine(ZONES)
    alerts = engine.process_batch([make_write_record(6, 100, ts=1000.0)])
    assert not any(a.rule == "unsafe_setpoint_write" for a in alerts)


def test_unsafe_setpoint_write_does_not_fire_on_ramped_change():
    engine = DetectionEngine(ZONES)
    records = [
        make_write_record(6, step, ts=1000.0 + i)
        for i, step in enumerate([0, 5, 10, 15, 20])
    ]
    alerts = engine.process_batch(records)
    assert not any(a.rule == "unsafe_setpoint_write" for a in alerts), "gradual 5-point ramps should not be treated as unsafe"


def test_unsafe_setpoint_write_coexists_with_unexpected_modbus_write():
    # Both rules are expected to co-fire on the same abrupt write -- this is
    # intentional defense-in-depth (see rule_unsafe_setpoint_write's docstring),
    # not something to be deduplicated away.
    engine = DetectionEngine(ZONES)
    baseline = make_write_record(6, 0, ts=1000.0)
    abrupt = make_write_record(6, 100, ts=1001.0)
    alerts = engine.process_batch([baseline, abrupt])
    rules = {a.rule for a in alerts}
    assert "unsafe_setpoint_write" in rules
    assert "unexpected_modbus_write" in rules
