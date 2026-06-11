import asyncio
import unittest

from app.api.routes import inspect
from app.api.schemas import InspectRequest
from tests.functional.test_attacks import PROFILES


class AttackProfileRegressionTest(unittest.TestCase):
    def test_attack_profiles_match_expected_status(self):
        mismatches = []

        for name, profile in PROFILES.items():
            request = InspectRequest(features=profile["features"])
            result = asyncio.run(inspect(request))
            actual = result["status"]
            expected = profile["expected"]

            if actual != expected:
                mismatches.append(
                    f"{name}: expected={expected} actual={actual} "
                    f"confidence={result.get('confidence')}"
                )

        self.assertEqual([], mismatches)


if __name__ == "__main__":
    unittest.main()
