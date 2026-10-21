from datetime import date
import unittest

from azure_php_scout.advisories import assess, parse_version


class AdvisoryTests(unittest.TestCase):
    def assessment(self, version, **extra):
        return assess(dict(php="yes", phpVersion=version, **extra), as_of=date(2026, 10, 21))

    def test_branch_specific_fixed_release_boundaries(self):
        for vulnerable, patched in [("8.2.34", "8.2.35"), ("8.3.35", "8.3.36"), ("8.4.26", "8.4.27"), ("8.5.11", "8.5.12")]:
            with self.subTest(version=vulnerable):
                result = self.assessment(vulnerable)
                self.assertEqual(result["assessment"], "potentially_affected")
                self.assertEqual(len(result["matches"]), 2)
                self.assertTrue(all(item["fixedVersion"] == patched for item in result["matches"]))
            with self.subTest(version=patched):
                self.assertEqual(self.assessment(patched)["assessment"], "no_catalog_match")

    def test_numeric_comparison_and_prerelease(self):
        self.assertEqual(self.assessment("8.3.9")["assessment"], "potentially_affected")
        self.assertEqual(self.assessment("8.5.12RC1")["assessment"], "potentially_affected")
        self.assertEqual(self.assessment("8.5.12-dev")["assessment"], "potentially_affected")
        self.assertEqual(self.assessment("8.5.12-rc")["assessment"], "potentially_affected")
        self.assertEqual(self.assessment("8.5.12-alpha")["assessment"], "potentially_affected")
        self.assertEqual(self.assessment("8.5.13")["assessment"], "no_catalog_match")

    def test_vendor_backport_uncertainty_is_preserved(self):
        result = self.assessment("8.2.29-1+deb12u2")
        self.assertEqual(result["assessment"], "potentially_affected")
        self.assertIn("vendor build suffix", result["assessmentBasis"])
        self.assertIn("backport", result["remediation"])

    def test_incomplete_conflicting_and_future_versions_need_verification(self):
        for version in ("8.3", "8.5.12garbage", "garbage", "8.6.0"):
            with self.subTest(version=version):
                self.assertEqual(self.assessment(version)["assessment"], "verify_version")
        self.assertEqual(self.assessment("8.2.35", phpVersions="8.2.35,8.2.34")["assessment"], "verify_version")
        self.assertEqual(self.assessment("8.2.35", phpVersions="8.3.36")["assessment"], "verify_version")

    def test_legacy_branch_is_eol_without_asserting_cve_exploitability(self):
        result = self.assessment("7.4.33")
        self.assertEqual(result["assessment"], "end_of_life")
        self.assertEqual(result["cves"], "")
        self.assertIn("vendor", result["remediation"])

    def test_configured_php_is_not_treated_as_observed_vulnerable_php(self):
        result = assess(dict(php="unknown", configuredPhpVersion="8.2.34"))
        self.assertEqual(result["assessment"], "configuration_only")
        self.assertFalse(result["matches"])

    def test_hidden_runtime_and_missing_php_evidence_are_distinct(self):
        self.assertEqual(assess(dict(php="probable", wordpress="yes"))["assessment"], "verify_version")
        self.assertEqual(assess(dict(php="unknown", wordpress="unknown"))["assessment"], "undetermined")

    def test_lifecycle_uses_date_boundaries(self):
        row = dict(php="yes", phpVersion="8.2.35")
        self.assertEqual(assess(row, as_of=date(2026, 12, 31))["phpSupport"], "security_fixes")
        self.assertEqual(assess(row, as_of=date(2027, 1, 1))["assessment"], "end_of_life")
        affected = assess(dict(php="yes", phpVersion="8.2.34"), as_of=date(2027, 1, 1))
        self.assertIn("supported PHP branch", affected["remediation"])
        self.assertNotIn("to 8.2.35", affected["remediation"])

    def test_historical_dates_do_not_use_future_catalog_or_eol_assumptions(self):
        result = assess(dict(php="yes", phpVersion="8.1.34"), as_of=date(2025, 12, 31))
        self.assertEqual(result["assessment"], "verify_version")
        self.assertEqual(result["phpSupport"], "unknown")
        self.assertFalse(result["matches"])


if __name__ == "__main__":
    unittest.main()
