"""Integration tests for the Day 3 master analysis pipeline."""

from pathlib import Path
import unittest
from unittest.mock import patch

from app.modules.analysis.email_analyzer import analyze_email
from app.modules.intel.geoip import lookup_ip


class EmailAnalyzerTests(unittest.TestCase):
    def test_spoofed_fixture_returns_the_forensic_contract(self) -> None:
        result = analyze_email(Path(__file__).resolve().parents[2] / "samples/spoofed_dmarc_fail/paypal_spoofed.eml")

        self.assertTrue({"evidence", "authentication", "relay_hops", "suspicious_flags", "risk_score"} <= result.keys())
        self.assertEqual(result["evidence"]["filename"], "paypal_spoofed.eml")
        self.assertEqual(len(result["evidence"]["sha256"]), 64)
        self.assertEqual(result["authentication"]["dmarc"]["result"], "fail")
        self.assertEqual(result["authentication"]["spf"]["result"], "fail")
        self.assertTrue(result["relay_hops"]["hops"])
        ml_points = sum(factor["points"] for factor in result["risk_score"]["factors"] if factor["code"] == "ml_phishing_content")
        self.assertIn(ml_points, {0, 8, 15})
        self.assertEqual(
            result["risk_score"]["score"],
            min(100, sum(factor["points"] for factor in result["risk_score"]["factors"])),
        )
        self.assertGreaterEqual(result["risk_score"]["score"], 70 + ml_points)
        self.assertIn(result["risk_score"]["category"], {"High Risk", "Critical Threat"})

    def test_private_addresses_are_not_sent_to_geoip_provider(self) -> None:
        result = lookup_ip("10.0.0.1")
        self.assertEqual(result["status"], "not_public")
        self.assertIsNone(result["location"])

    def test_spear_phishing_indicators_are_not_classified_as_legitimate(self) -> None:
        raw = b"""From: MUJ IT Service Desk <it-helpdesk@muj-manipaI.edu>\r
To: student@example.edu\r
Subject: Action Required: Your mailbox will be deactivated\r
Date: Tue, 01 Sep 2026 10:00:00 +0000\r
Message-ID: <spear@example.edu>\r
Authentication-Results: mx.example.edu; dkim=none; spf=none smtp.mailfrom=muj-manipaI.edu; dmarc=none\r
Received: from relay.example ([154.204.27.88]) by mx.example.edu with SMTP; Tue, 01 Sep 2026 10:00:00 +0000\r
Content-Type: text/plain; charset=utf-8\r
\r
Revalidate your account at http://mujerp-revalidate.muj-manipaI.edu.webportal-id.com/student/login\r
"""
        result = analyze_email(raw, filename="spear_phish.eml")

        self.assertEqual(result["risk_score"]["category"], "Critical Threat")
        self.assertLessEqual(result["risk_score"]["score"], 100)
        self.assertIn("ml_content_analysis", result)
        self.assertTrue(result["suspicious_flags"]["lookalike_domain"])
        self.assertTrue(result["suspicious_flags"]["has_deceptive_url_host"])

    def test_ceo_giftcard_fixture_is_flagged_despite_passing_gmail_authentication(self) -> None:
        fixture = Path(__file__).resolve().parents[2] / "samples/bec_wire_fraud/ceo_giftcard.eml"
        low_model_signal = {"enabled": True, "status": "success", "prediction": "legitimate", "phishing_probability": 0.3449}
        with patch("app.modules.analysis.email_analyzer.analyze_content", return_value=low_model_signal):
            result = analyze_email(fixture)
        flags = result["suspicious_flags"]
        self.assertEqual(result["authentication"]["overall_verdict"], "pass")
        self.assertTrue(flags["financial_request_language"])
        self.assertTrue(flags["verification_suppression_language"])
        self.assertTrue(flags["external_authority_impersonation"])
        self.assertTrue(flags["sensitive_recipient_targeted"])
        self.assertTrue(flags["date_weekday_mismatch"])
        self.assertEqual(result["risk_score"]["score"], 75)
        self.assertEqual(result["risk_score"]["category"], "High Risk")
        self.assertEqual(result["ml_content_analysis"]["prediction"], "legitimate")


if __name__ == "__main__":
    unittest.main()
