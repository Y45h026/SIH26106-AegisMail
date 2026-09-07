"""End-to-end API and report tests using committed EML fixtures."""

from pathlib import Path
import unittest

from fastapi.testclient import TestClient

from app.main import app


FIXTURE = Path("samples/spoofed_dmarc_fail/paypal_spoofed.eml")


class ApiEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.raw = FIXTURE.read_bytes()

    def test_upload_analysis_and_pdf_report(self) -> None:
        response = self.client.post("/api/v1/analyze", files={"file": (FIXTURE.name, self.raw, "message/rfc822")})
        self.assertEqual(response.status_code, 200)
        analysis = response.json()
        self.assertEqual(analysis["evidence"]["filename"], FIXTURE.name)
        self.assertEqual(analysis["authentication"]["dmarc"]["result"], "fail")
        self.assertIn("risk_score", analysis)
        report = self.client.post("/api/v1/report", json=analysis)
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.headers["content-type"], "application/pdf")
        self.assertTrue(report.content.startswith(b"%PDF"))

    def test_non_eml_upload_is_rejected(self) -> None:
        response = self.client.post("/api/v1/analyze", files={"file": ("evidence.txt", self.raw, "text/plain")})
        self.assertEqual(response.status_code, 415)


if __name__ == "__main__":
    unittest.main()
