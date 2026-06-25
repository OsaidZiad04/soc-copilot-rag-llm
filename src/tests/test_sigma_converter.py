import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parents[1]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from modules.sigma import SigmaConversionEngine


SAMPLE_RULE = """
title: Suspicious PowerShell Network Connection
id: soc-copilot-test-powershell-network
description: Detects PowerShell connecting to a suspicious remote IP address.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection_process:
    Image|endswith:
      - powershell.exe
  selection_ip:
    DestinationIp|contains:
      - 185.220.101.45
  condition: selection_process and selection_ip
level: high
"""


class SigmaConversionEngineTests(unittest.TestCase):

    def setUp(self):
        self.engine = SigmaConversionEngine()

    def test_validate_parses_sigma_rule(self):
        result = self.engine.validate(SAMPLE_RULE, filename="rule.yml")

        self.assertTrue(result["valid"])
        self.assertEqual(result["rule"]["title"], "Suspicious PowerShell Network Connection")
        self.assertEqual(result["rule"]["condition"], "selection_process and selection_ip")
        self.assertIn("selection_process", result["selectors"])

    def test_convert_selected_platforms(self):
        result = self.engine.convert(
            SAMPLE_RULE,
            platforms=["splunk", "sentinel_kql", "suricata", "crowdstrike", "google_secops", "osquery_sql"],
            filename="rule.yaml",
        )

        self.assertTrue(result["valid"])
        self.assertEqual(len(result["conversions"]), 6)
        queries = {item["platform"]: item["query"] for item in result["conversions"]}
        self.assertIn("search index=*", queries["splunk"])
        self.assertIn("DeviceEvents", queries["sentinel_kql"])
        self.assertIn("alert tcp", queries["suricata"])
        self.assertIn("ImageFileName", queries["crowdstrike"])
        self.assertIn("rule suspicious_powershell_network_connection", queries["google_secops"])
        self.assertIn("SELECT * FROM process_events", queries["osquery_sql"])

    def test_supported_platforms_include_extended_options(self):
        platforms = {item["platform"] for item in self.engine.supported_platforms()}

        self.assertIn("opensearch_dql", platforms)
        self.assertIn("sumologic", platforms)
        self.assertIn("graylog", platforms)
        self.assertIn("logscale", platforms)
        self.assertIn("carbon_black", platforms)
        self.assertIn("google_secops", platforms)
        self.assertIn("osquery_sql", platforms)

    def test_unsupported_operator_returns_structured_error(self):
        rule = SAMPLE_RULE.replace("Image|endswith", "Image|cidr")
        result = self.engine.validate(rule, filename="rule.yml")

        self.assertFalse(result["valid"])
        self.assertTrue(any(error["code"] == "unsupported_operator" for error in result["errors"]))

    def test_all_of_condition_expands_without_trailing_wildcard(self):
        rule = """
title: All Of Selection
detection:
  selection_one:
    Image|endswith: cmd.exe
  selection_two:
    CommandLine|contains: whoami
  condition: all of selection_*
"""
        result = self.engine.convert(rule, platforms=["splunk"])
        query = result["conversions"][0]["query"]

        self.assertTrue(result["valid"])
        self.assertIn("AND", query)
        self.assertNotIn("selection_*", query)
        self.assertFalse(query.endswith("*"))

    def test_numeric_of_condition_expands_to_boolean_combinations(self):
        rule = """
title: Numeric Of Selection
detection:
  selection_one:
    Image|endswith: cmd.exe
  selection_two:
    CommandLine|contains: whoami
  selection_three:
    CommandLine|contains: net user
  condition: 2 of selection_*
"""
        result = self.engine.convert(rule, platforms=["splunk"])
        query = result["conversions"][0]["query"]

        self.assertTrue(result["valid"])
        self.assertTrue(any(warning["code"] == "numeric_of_condition" for warning in result["warnings"]))
        self.assertIn("whoami", query)
        self.assertIn("net user", query)

    def test_unknown_condition_selector_returns_structured_error(self):
        rule = """
title: Missing Selector
detection:
  selection_one:
    Image: cmd.exe
  condition: selection_one and selection_missing
"""
        result = self.engine.validate(rule, filename="rule.yml")

        self.assertFalse(result["valid"])
        self.assertTrue(any(error["code"] == "unknown_condition_selector" for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
