import math
from typing import ClassVar, Optional

from pydantic import BaseModel, ConfigDict, field_validator


FEATURE_COLUMNS = [
    "dur",
    "proto",
    "service",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
]

NUMERIC_FIELDS = tuple(name for name in FEATURE_COLUMNS if name not in {"proto", "service", "state"})


class TrafficRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dur: float
    proto: str
    service: str
    state: str
    spkts: float
    dpkts: float
    sbytes: float
    dbytes: float
    rate: float
    sttl: float
    dttl: float
    sload: float
    dload: float
    sloss: float
    dloss: float
    sinpkt: float
    dinpkt: float
    sjit: float
    djit: float
    swin: float
    stcpb: float
    dtcpb: float
    dwin: float
    tcprtt: float
    synack: float
    ackdat: float
    smean: float
    dmean: float
    trans_depth: float
    response_body_len: float
    ct_srv_src: float
    ct_state_ttl: float
    ct_dst_ltm: float
    ct_src_dport_ltm: float
    ct_dst_sport_ltm: float
    ct_dst_src_ltm: float
    is_ftp_login: float
    ct_ftp_cmd: float
    ct_flw_http_mthd: float
    ct_src_ltm: float
    ct_srv_dst: float
    is_sm_ips_ports: float

    _numeric_fields: ClassVar[tuple[str, ...]] = NUMERIC_FIELDS

    @field_validator(*NUMERIC_FIELDS)
    @classmethod
    def finite_number(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("numeric fields must be finite")
        return value


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: str


class ModelInfoResponse(BaseModel):
    model_name: str
    feature_count: int
    feature_columns: list[str]
    label_mapping: dict[str, str]
    metrics: dict[str, float]


class PredictionResponse(BaseModel):
    prediction: str
    prediction_label: int
    confidence: Optional[float]
    probabilities: dict[str, float]
