import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import threat_intel

#below are unit tests for the functions in threat_intel.py. 
class TestValidateIP(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(threat_intel.validate_ip("8.8.8.8"))

    def test_valid_ipv6(self):
        self.assertTrue(threat_intel.validate_ip("2001:4860:4860::8888"))

    def test_invalid_ip(self):
        self.assertFalse(threat_intel.validate_ip("invalid-ip"))

    def test_empty_ip(self):
        self.assertFalse(threat_intel.validate_ip(""))


class TestClassifyThreat(unittest.TestCase):
    def test_high_classification(self):
        self.assertEqual(
            threat_intel.classify_threat({"malicious": 10}), "High"
        )

    def test_medium_classification(self):
        self.assertEqual(
            threat_intel.classify_threat({"malicious": 5}), "Medium"
        )

    def test_low_classification(self):
        self.assertEqual(
            threat_intel.classify_threat({"malicious": 1}), "Low"
        )

    def test_no_detections(self):
        self.assertEqual(
            threat_intel.classify_threat({"malicious": 0}), "No detections"
        )

    def test_missing_statistics(self):
        self.assertEqual(threat_intel.classify_threat({}), "Unknown")

    def test_missing_malicious_count(self):
        self.assertEqual(
            threat_intel.classify_threat({"harmless": 50}), "Unknown"
        )


class TestLoadIOCs(unittest.TestCase):
    def test_loads_and_strips_ip_addresses(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "iocs.txt"
            file_path.write_text(
                "8.8.8.8\n\n  1.1.1.1  \n",
                encoding="utf-8",
            )

            result = threat_intel.load_iocs(str(file_path))

            self.assertEqual(result, ["8.8.8.8", "1.1.1.1"])


class TestLookupIP(unittest.TestCase):
    @patch("threat_intel.requests.get")
    def test_successful_lookup(self, mock_get):
        expected_result = {
            "data": {
                "attributes": {
                    "reputation": 100,
                    "last_analysis_stats": {"malicious": 0},
                }
            }
        }

        response = Mock()
        response.status_code = 200
        response.json.return_value = expected_result
        mock_get.return_value = response

        with patch.object(threat_intel, "API_KEY", "test-api-key"):
            result = threat_intel.lookup_ip("8.8.8.8")

        self.assertEqual(result, expected_result)
        mock_get.assert_called_once_with(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": "test-api-key"},
            timeout=15,
        )

    @patch("threat_intel.requests.get")
    def test_rate_limit_returns_none(self, mock_get):
        response = Mock()
        response.status_code = 429
        mock_get.return_value = response

        with patch.object(threat_intel, "API_KEY", "test-api-key"):
            result = threat_intel.lookup_ip("8.8.8.8")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
