"""Unit tests for the offline content threat engine."""

import unittest

from app.modules.content.homoglyph import analyze_sender_domain, check_lookalike_domain, levenshtein_distance
from app.modules.content.nlp_intent import analyze_email_intent
from app.modules.scoring.risk_engine import score_email_risk


class HomoglyphTests(unittest.TestCase):
    def test_levenshtein_and_ascii_typosquat(self) -> None:
        self.assertEqual(levenshtein_distance("paypal", "paypa1"), 1)
        result = check_lookalike_domain("billing@paypa1.com")
        self.assertTrue(result["is_impersonation_suspected"])
        self.assertIn("paypal", result["matched_brands"])

    def test_cyrillic_homoglyph_and_brand_keyword(self) -> None:
        homoglyph = analyze_sender_domain("alerts@pаypal.com")
        keyword = analyze_sender_domain("alerts@paypal-security-update.com")
        self.assertTrue(any(item["type"] == "homoglyph" for item in homoglyph["findings"]))
        self.assertTrue(any(item["type"] == "brand_keyword_combination" for item in keyword["findings"]))

    def test_legitimate_domain_is_not_flagged(self) -> None:
        self.assertFalse(analyze_sender_domain("service@paypal.com")["is_impersonation_suspected"])


class IntentTests(unittest.TestCase):
    def test_bec_language_scores_high(self) -> None:
        result = analyze_email_intent(
            "Urgent wire transfer",
            "I am in a meeting, do not call. Handle this immediately and buy gift cards today.",
        )
        self.assertTrue(result["is_high_risk_bec"])
        self.assertIn("financial_fraud", result["detected_intents"])
        self.assertIn("authority_fraud", result["detected_intents"])

    def test_benign_content_scores_zero(self) -> None:
        self.assertEqual(analyze_email_intent("Weekly update", "The meeting is next Tuesday.")["urgency_deception_score"], 0.0)


class RiskEngineTests(unittest.TestCase):
    def test_all_signals_are_explained_and_bounded(self) -> None:
        result = score_email_risk(
            authentication={"dmarc": "fail", "spf": "fail"},
            domain={"is_impersonation_suspected": True, "age_days": 10},
            headers={"reply_to_mismatch": True, "has_message_id": False},
            content={"urgency_deception_score": 0.9},
            urls={"has_ip_based_url": True},
        )
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["category"], "Critical Threat")
        self.assertEqual(result["factor_count"], 8)

    def test_category_boundaries(self) -> None:
        self.assertEqual(score_email_risk(domain={"age_days": 10})["category"], "Legitimate")
        self.assertEqual(score_email_risk(authentication={"dmarc": "fail"}, domain={"age_days": 10})["category"], "Suspicious")

    def test_safe_email_stays_below_green_threshold(self) -> None:
        result = score_email_risk(
            authentication={"dmarc": "pass", "spf": "pass"},
            domain={"age_days": 365},
            headers={"has_message_id": True, "reply_to_mismatch": False},
            content={"urgency_deception_score": 0.0},
            urls={"has_ip_based_url": False},
        )
        self.assertLess(result["score"], 25)
        self.assertEqual(result["color"], "green")
        self.assertTrue(result["is_safe"])

    def test_correlated_phishing_signals_cross_red_threshold(self) -> None:
        result = score_email_risk(
            authentication={"dmarc": "fail", "spf": "fail"},
            domain={"is_impersonation_suspected": True},
            content={"urgency_deception_score": 0.9},
        )
        self.assertGreater(result["score"], 75)
        self.assertEqual(result["color"], "red")
        self.assertTrue(result["is_red_risk"])


if __name__ == "__main__":
    unittest.main()
