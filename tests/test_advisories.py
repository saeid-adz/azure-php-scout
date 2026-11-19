from datetime import date
import unittest

from azure_php_scout.advisories import assess, assess_nginx, enrich, parse_nginx_version, parse_version


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


class NginxAdvisoryTests(unittest.TestCase):
    def assessment(self, version, http2="yes", **extra):
        return assess_nginx(dict(nginx="yes", nginxVersion=version, http2=http2, **extra))

    def test_range_boundaries_and_fixed_releases(self):
        for version in ("1.19.7", "1.24.0", "1.30.6", "1.31.0", "1.31.8"):
            with self.subTest(version=version):
                result = self.assessment(version)
                self.assertEqual(result["nginxAssessment"], "potentially_affected")
                self.assertEqual(result["nginxRiskLevel"], "critical")
        for version in ("1.30.7", "1.31.9", "1.32.0"):
            with self.subTest(version=version):
                self.assertEqual(self.assessment(version)["nginxAssessment"], "no_catalog_match")

    def test_each_cve_has_its_own_lower_bound(self):
        self.assertEqual(self.assessment("1.12.0")["nginxCves"], "CVE-2026-123007")
        self.assertEqual(self.assessment("1.19.6")["nginxCves"], "CVE-2026-123007")
        self.assertEqual(self.assessment("1.19.7")["nginxCves"], "CVE-2026-123633, CVE-2026-123007")
        self.assertEqual(self.assessment("1.9.4")["nginxAssessment"], "no_catalog_match")

    def test_fixed_version_matches_branch(self):
        self.assertEqual(self.assessment("1.31.3")["matches"][0]["fixedVersion"], "1.31.9")
        self.assertEqual(self.assessment("1.30.2")["matches"][0]["fixedVersion"], "1.30.7")
        self.assertEqual(self.assessment("1.24.0")["matches"][0]["fixedVersion"], "1.30.7")

    def test_http2_not_confirmed_lowers_certainty_not_visibility(self):
        for http2 in ("no", "unknown"):
            result = self.assessment("1.30.6", http2=http2)
            self.assertEqual((result["nginxAssessment"], result["nginxRiskLevel"]), ("verify_http2", "high"))
            self.assertIn("1.30.7", result["nginxRemediation"])

    def test_hidden_or_malformed_version_needs_verification(self):
        self.assertEqual(self.assessment("")["nginxAssessment"], "verify_version")
        self.assertEqual(self.assessment("1.30")["nginxAssessment"], "verify_version")
        self.assertIsNone(parse_nginx_version("1.30"))

    def test_no_signal_and_distribution_build(self):
        self.assertEqual(assess_nginx(dict(nginx="unknown", nginxVersion="1.24.0"))["nginxAssessment"], "undetermined")
        self.assertIn("distribution build", self.assessment("1.24.0", server="nginx/1.24.0 (Ubuntu)")["nginxBasis"])

    def test_enrich_keeps_php_and_nginx_assessments_independent(self):
        row = enrich(dict(php="yes", phpVersion="8.3.35", nginx="yes", nginxVersion="1.30.6", http2="yes"))
        self.assertEqual((row["assessment"], row["nginxAssessment"]), ("potentially_affected", "potentially_affected"))
        self.assertEqual(enrich(dict(php="yes", phpVersion="8.3.36"))["nginxAssessment"], "undetermined")
