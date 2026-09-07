"""Integration tests for the Day 3 master analysis pipeline."""

from pathlib import Path
import unittest

from app.modules.analysis.email_analyzer import analyze_email
from app.modules.intel.geoip import lookup_ip


class EmailAnalyzerTests(unittest.TestCase):
    def test_spoofed_fixture_returns_the_forensic_contract(self) -> None:
        result = analyze_email(Path("samples/spoofed_dmarc_fail/paypal_spoofed.eml"))

        self.assertTrue({"evidence", "authentication", "relay_hops", "suspicious_flags", "risk_score"} <= result.keys())
        self.assertEqual(result["evidence"]["filename"], "paypal_spoofed.eml")
        self.assertEqual(len(result["evidence"]["sha256"]), 64)
        self.assertEqual(result["authentication"]["dmarc"]["result"], "fail")
        self.assertEqual(result["authentication"]["spf"]["result"], "fail")
        self.assertTrue(result["relay_hops"]["hops"])
        self.assertEqual(result["risk_score"]["score"], 45)
        self.assertEqual(result["risk_score"]["category"], "Suspicious")

    def test_private_addresses_are_not_sent_to_geoip_provider(self) -> None:
        result = lookup_ip("10.0.0.1")
        self.assertEqual(result["status"], "not_public")
        self.assertIsNone(result["location"])


if __name__ == "__main__":
    unittest.main()
