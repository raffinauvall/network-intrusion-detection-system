import asyncio
import math
import tempfile
import threading
import unittest
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

from app.api.routes import get_blocks, get_status, healthz, inspect
from app.api.schemas import InspectRequest
from app.core.detector import monitor_loop
from app.services import blocker
from app.services import auth
from app.services.auth import is_authorized
from app.services.blocker import block_ip, is_blocked, load_blocklist
from app.services.model_service import model_service
from app.state import blocked_ips, blocked_ips_lock, latest_prediction, sniffer_status


class InspectValidationTest(unittest.TestCase):
    def test_rejects_non_finite_feature_values(self):
        with self.assertRaises(ValidationError):
            InspectRequest(features={"dur": math.inf})

    def test_rejects_too_many_features(self):
        with self.assertRaises(ValidationError):
            InspectRequest(features={f"feature_{i}": float(i) for i in range(300)})

    def test_rejects_unknown_feature_names(self):
        request = InspectRequest(features={"not_a_model_feature": 1.0})

        with self.assertRaises(HTTPException) as error:
            asyncio.run(inspect(request))

        self.assertEqual(error.exception.status_code, 422)
        self.assertIn("not_a_model_feature", error.exception.detail["unknown_features"])

    def test_accepts_known_sparse_feature_payload(self):
        request = InspectRequest(features={"sttl": 64.0, "proto_tcp": 1.0})
        result = asyncio.run(inspect(request))

        self.assertIn(result["status"], {"OK", "ATTACK"})
        self.assertEqual(result["used_features"], 2)
        self.assertEqual(result["defaulted_features"], len(model_service.features) - 2)
        self.assertIn("normal", result["probabilities"])
        self.assertIn("attack", result["probabilities"])


class StatusBaselineTest(unittest.TestCase):
    def test_monitor_loop_publishes_ok_baseline_on_startup(self):
        stop_event = threading.Event()

        latest_prediction.clear()
        latest_prediction.update({"status": "INITIALIZING", "prediction": 0})
        stop_event.set()

        monitor_loop(stop_event)

        self.assertEqual(latest_prediction["status"], "OK")
        self.assertEqual(latest_prediction["prediction"], 0)
        self.assertEqual(latest_prediction["confidence"], 1.0)
        self.assertEqual(latest_prediction["active_flows"], 0)
        self.assertIsNone(latest_prediction["attack_flow"])

    def test_status_response_includes_sniffer_state(self):
        latest_prediction.clear()
        latest_prediction.update({"status": "OK", "prediction": 0})
        sniffer_status.update({
            "enabled": False,
            "status": "disabled",
            "interfaces": [],
            "error": None,
        })

        result = asyncio.run(get_status())

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["sniffer"]["status"], "disabled")
        self.assertFalse(result["sniffer"]["enabled"])

    def test_healthz_reports_model_loaded(self):
        result = asyncio.run(healthz())

        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["model_loaded"])
        self.assertGreater(result["feature_count"], 0)


class BlockingTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_blocklist_path = blocker.BLOCKLIST_PATH
        blocker.BLOCKLIST_PATH = Path(self.temp_dir.name) / "blocked_ips.json"
        with blocked_ips_lock:
            blocked_ips.clear()

    def tearDown(self):
        blocker.BLOCKLIST_PATH = self.original_blocklist_path
        self.temp_dir.cleanup()
        with blocked_ips_lock:
            blocked_ips.clear()

    def test_block_ip_rejects_loopback(self):
        result = block_ip("127.0.0.1", confidence=0.99)

        self.assertFalse(result["blocked"])
        self.assertFalse(is_blocked("127.0.0.1"))

    def test_block_ip_adds_source_to_internal_blocklist(self):
        result = block_ip("192.0.2.10", confidence=0.91)

        self.assertTrue(result["blocked"])
        self.assertTrue(is_blocked("192.0.2.10"))

    def test_blocks_endpoint_lists_blocked_ips(self):
        block_ip("192.0.2.11", confidence=0.92)

        result = asyncio.run(get_blocks())

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["blocked_ips"][0]["ip"], "192.0.2.11")

    def test_blocklist_persists_to_disk(self):
        block_ip("192.0.2.12", confidence=0.93)
        with blocked_ips_lock:
            blocked_ips.clear()

        load_blocklist()

        self.assertTrue(is_blocked("192.0.2.12"))


class AuthTest(unittest.TestCase):
    def tearDown(self):
        auth.API_TOKEN = ""

    def test_auth_allows_requests_when_token_is_not_configured(self):
        class Request:
            headers = {}

        self.assertTrue(is_authorized(Request()))

    def test_auth_requires_matching_token_when_configured(self):
        auth.API_TOKEN = "secret-token"

        class BadRequest:
            headers = {"authorization": "Bearer wrong"}

        class GoodRequest:
            headers = {"authorization": "Bearer secret-token"}

        self.assertFalse(is_authorized(BadRequest()))
        self.assertTrue(is_authorized(GoodRequest()))


if __name__ == "__main__":
    unittest.main()
