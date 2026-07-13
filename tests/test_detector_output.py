from app.core.detector import _flow_info, _history_event
from app.core.flow import FlowRecord


def test_attack_output_includes_attacker_ip_and_target_port():
    flow = FlowRecord("198.51.100.10", "203.0.113.20", 44444, 2326, 6)

    info = _flow_info(flow, 0.9, "model")
    event = _history_event(flow, 0.9)

    assert info["src"] == "198.51.100.10"
    assert info["dport"] == 2326
    assert event["attacker_ip"] == "198.51.100.10"
    assert event["target_port"] == 2326
