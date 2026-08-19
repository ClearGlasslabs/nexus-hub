import json
import unittest

from artemis_blue_team import ArtemisScanner
from artemis_blue_team.scanner import ScanRequest, json_report


class ArtemisBlueTeamTests(unittest.TestCase):
    def setUp(self):
        self.scanner = ArtemisScanner()

    def test_secret_is_suppressed_and_blocks_publication(self):
        report = self.scanner.scan(
            b"image-bytes",
            ScanRequest("brand_protection", "AUTHORIZED"),
            ocr_text="AWS key AKIA1234567890ABCDEF and password-like material",
        )
        self.assertEqual(report["classification"], "DO_NOT_SHARE")
        self.assertEqual(report["risk_level"], "CRITICAL")
        self.assertTrue(report["secret_rotation_required"])
        rendered = json_report(report)
        self.assertNotIn("AKIA1234567890ABCDEF", rendered)

    def test_face_has_no_identity_inference(self):
        report = self.scanner.scan(
            b"image-bytes",
            ScanRequest("secure_publication", "AUTHORIZED"),
            visual_labels=["face"],
        )
        self.assertEqual(report["risk_level"], "HIGH")
        self.assertTrue(report["human_review_required"])
        observations = " ".join(x["observation"] for x in report["findings"])
        self.assertIn("identity inference was not performed", observations)

    def test_qr_is_not_decoded(self):
        report = self.scanner.scan(
            b"image-bytes",
            ScanRequest("secure_publication", "AUTHORIZED"),
            visual_labels=["qr_code"],
        )
        self.assertEqual(report["classification"], "INTERNAL_ONLY")
        self.assertIn("not decoded", report["findings"][0]["observation"])

    def test_unclear_authorization_fails_closed(self):
        report = self.scanner.scan(
            b"image-bytes",
            ScanRequest("", "UNCLEAR"),
        )
        self.assertEqual(report["authorization_status"], "UNCLEAR")
        self.assertNotEqual(report["classification"], "SAFE_TO_SHARE")

    def test_report_is_json_serializable(self):
        report = self.scanner.scan(
            b"image-bytes",
            ScanRequest("compliance_review", "AUTHORIZED"),
        )
        parsed = json.loads(json_report(report))
        self.assertEqual(parsed["audit"]["stored_data"], "HASH_AND_MINIMIZED_REPORT_ONLY")
        self.assertEqual(parsed["retention"]["original_image"], "DELETE_AFTER_PROCESSING")


if __name__ == "__main__":
    unittest.main()
