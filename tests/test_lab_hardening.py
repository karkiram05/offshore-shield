"""Regression tests for the lab's exposure and output-hygiene fixes."""
import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scenarios.artifacts import repo_relative  # noqa: E402

LAB_SERVICES = [
    "lab/plc_sim/turbine_modbus_server.py",
    "lab/plc_sim/hvac_modbus_server.py",
    "lab/services/mgmt_banner_service.py",
    "lab/tap/network_tap.py",
]


def host_default(path: Path) -> str:
    """The default of the script's `--host` argparse option."""
    for node in ast.walk(ast.parse(path.read_text())):
        if (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument"
                and node.args and getattr(node.args[0], "value", None) == "--host"):
            for kw in node.keywords:
                if kw.arg == "default":
                    return kw.value.value
    raise AssertionError(f"{path} has no --host option")


def test_lab_services_listen_on_loopback_by_default():
    # The simulators are unauthenticated and the turbine one has a writable
    # setpoint register: binding 0.0.0.0 by default put them on the LAN.
    for rel in LAB_SERVICES:
        assert host_default(REPO / rel) == "127.0.0.1", rel


def test_results_paths_are_repo_relative():
    assert repo_relative(REPO / "lab" / "network_zones.json") == "lab/network_zones.json"
    assert repo_relative("/somewhere/else/zones.json") == "zones.json"


def test_committed_outputs_contain_no_absolute_paths():
    leaked = []
    for folder in ("scenarios/results", "dashboard", "data"):
        for path in (REPO / folder).rglob("*"):
            if path.is_file() and path.suffix in {".json", ".jsonl", ".csv", ".html"}:
                text = path.read_text(errors="ignore")
                if "/home/" in text or "/Users/" in text or "/root/" in text:
                    leaked.append(str(path.relative_to(REPO)))
    assert leaked == []


def test_trustgraph_dependency_is_pinned_to_a_commit():
    line = next(l for l in (REPO / "requirements.txt").read_text().splitlines()
                if l.startswith("trustgraph"))
    ref = line.rsplit("@", 1)[1]
    assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), line
