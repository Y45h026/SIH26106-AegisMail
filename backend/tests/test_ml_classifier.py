"""Tests use only a tiny synthetic fixture; it is never a released model."""
from __future__ import annotations

import sys
import tempfile
import unittest
import subprocess
import csv
from pathlib import Path

import joblib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.modules.content import ml_classifier
from app.modules.scoring.risk_engine import score_email_risk


class MlClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.original_path = ml_classifier.MODEL_PATH
        ml_classifier.MODEL_PATH = Path(self.temp.name) / "model.joblib"
        ml_classifier.clear_model_cache()

    def tearDown(self) -> None:
        ml_classifier.MODEL_PATH = self.original_path
        ml_classifier.clear_model_cache()
        self.temp.cleanup()

    def test_missing_artifact_is_structured_unavailable(self) -> None:
        result = ml_classifier.analyze_content("Hello", "Meeting at noon")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["status"], "model_unavailable")

    def test_corrupt_artifact_fails_closed(self) -> None:
        ml_classifier.MODEL_PATH.write_bytes(b"not a trusted model")
        result = ml_classifier.analyze_content("Hello", "Message body")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["status"], "model_unavailable")

    def test_empty_input_and_output_contract(self) -> None:
        result = ml_classifier.analyze_content(None, None)
        self.assertEqual(result["status"], "empty_input")
        self.assertEqual(result["input_summary"]["body_character_count"], 0)
        self.assertIn("limitations", result)

    def test_valid_artifact_probability_and_indicators_are_bounded(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline

        texts = ["subject verify account body click here secure login" for _ in range(6)] + [
            "subject picnic plans body see you at lunch tomorrow" for _ in range(6)
        ]
        labels = [1] * 6 + [0] * 6
        pipeline = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2))), ("classifier", LogisticRegression())])
        pipeline.fit(texts, labels)
        joblib.dump(pipeline, ml_classifier.MODEL_PATH)
        ml_classifier.clear_model_cache()
        result = ml_classifier.analyze_content("Verify account", "Click here to secure login")
        self.assertTrue(result["enabled"])
        self.assertGreaterEqual(result["phishing_probability"], 0)
        self.assertLessEqual(result["phishing_probability"], 1)
        self.assertLessEqual(len(result["top_indicators"]), 3)
        self.assertNotIn("body", [indicator["term"] for indicator in result["top_indicators"]])

    def test_ml_risk_signal_is_limited_to_documented_points(self) -> None:
        result = score_email_risk(ml_content_analysis={"enabled": True, "prediction": "phishing", "phishing_probability": 0.9})
        self.assertEqual(result["factors"][-1]["points"], 15)
        self.assertEqual(result["score"], 15)
        moderate = score_email_risk(ml_content_analysis={"enabled": True, "prediction": "phishing", "phishing_probability": 0.75})
        self.assertEqual(moderate["score"], 8)

    def test_training_cli_evaluates_saves_report_and_reloads_pipeline(self) -> None:
        root = Path(__file__).resolve().parents[2]
        data = Path(self.temp.name) / "tiny.csv"
        artifact = Path(self.temp.name) / "trained.joblib"
        report = Path(self.temp.name) / "report.json"
        manifest = Path(self.temp.name) / "manifest.json"
        with data.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["subject", "body", "label"])
            writer.writeheader()
            for i in range(12):
                writer.writerow({"subject": f"Verify account {i}", "body": f"click here secure login offer {i}", "label": "phishing"})
                writer.writerow({"subject": f"Team lunch {i}", "body": f"see you tomorrow picnic plans {i}", "label": "ham"})
        command = [sys.executable, str(root / "backend/training/train_phishing_classifier.py"), str(data),
                   "--label-column", "label", "--legitimate-label", "ham", "--phishing-label", "phishing",
                   "--subject-column", "subject", "--body-columns", "body", "--output", str(artifact), "--report", str(report), "--manifest", str(manifest)]
        completed = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(report.is_file())
        self.assertTrue(manifest.is_file())
        loaded = joblib.load(artifact)
        probability = loaded.predict_proba(["subject: verify account body: click here secure login"])[0][1]
        self.assertGreaterEqual(probability, 0)
        self.assertLessEqual(probability, 1)


if __name__ == "__main__":
    unittest.main()
