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
        self.assertEqual(result["risk_score"]["score"], 70)
        self.assertEqual(result["risk_score"]["category"], "High Risk")

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
        self.assertTrue(result["suspicious_flags"]["lookalike_domain"])
        self.assertTrue(result["suspicious_flags"]["has_deceptive_url_host"])


if __name__ == "__main__":
    unittest.main()
