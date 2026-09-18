"""Risk scoring: same design as SentinelFlow's risk engine
(github.com/karkiram05/sentinelflow, backend/app/detection/risk.py),
reimplemented standalone here rather than imported cross-repo, because two
independent portfolio projects shouldn't have a runtime dependency on each
other's package layout. The scoring idea carries over unchanged: base rule
confidence, blended with a small bounded boost for a source that keeps
triggering alerts.

Two inputs feed the score: rule confidence (each detection rule states how
confident it is in its own finding) and how often the same source has
already triggered an alert in this session. Neither asset criticality nor
external threat intel is modeled -- see docs/architecture.md's roadmap.
"""

REPEAT_BOOST_PER_PRIOR_ALERT = 4.0
REPEAT_BOOST_CAP = 20.0


def base_score(confidence: float) -> float:
    """confidence in [0, 1] -> a 0-100 score."""
    return max(0.0, min(100.0, confidence * 100.0))


def repeat_offender_boost(prior_alert_count: int) -> float:
    """Small, capped score boost for a source with prior alerts."""
    if prior_alert_count <= 0:
        return 0.0
    return min(REPEAT_BOOST_CAP, prior_alert_count * REPEAT_BOOST_PER_PRIOR_ALERT)


def apply_repeat_offender_boost(score: float, prior_alert_count: int) -> float:
    return min(100.0, score + repeat_offender_boost(prior_alert_count))


def severity_band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
