from app.core.features import build_features_from_flow
from app.core.flow import FlowRecord
from app.schemas import FEATURE_COLUMNS


def test_live_feature_extractor_emits_42_raw_fields():
    flow = FlowRecord("192.0.2.10", "192.0.2.20", 12345, 80, 6)
    flow.add_src_packet(1000.0, 60, 64, "S", 10, 1024)
    flow.add_dst_packet(1000.1, 60, 64, "SA", 20, 1024)
    flow.update_state("SA")

    features = build_features_from_flow(flow)

    assert list(features) == FEATURE_COLUMNS
    assert len(features) == 42
    assert features["proto"] == "tcp"
    assert features["service"] == "http"
    assert features["state"] == "CON"
    assert "proto_tcp" not in features
    assert "service_http" not in features
    assert "state_CON" not in features
