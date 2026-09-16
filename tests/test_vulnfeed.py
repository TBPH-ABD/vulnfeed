"""Tests for vulnfeed CVE parsing, filtering, caching, and CLI."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

import vulnfeed
from tests.support.fakes import capture_cli, http_fake
from vulnfeed import (MAX_DATE_RANGE_DAYS, extract_metric, parse_vulnerability,
                      search)


def cve_entry(cve_id="CVE-2021-44228", severity="CRITICAL", score=10.0,
              vector="NETWORK", description="A serious flaw.",
              metric_key="cvssMetricV31", published="2021-12-10T10:15:09.143",
              cwes=("CWE-502",), refs=("https://example.test/advisory",)):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": "2023-04-03T19:56:00.000",
            "descriptions": [
                {"lang": "es", "value": "Una falla."},
                {"lang": "en", "value": description},
            ],
            "metrics": {
                metric_key: [{
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "attackVector": vector,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                }]
            },
            "weaknesses": [
                {"description": [{"value": c} for c in cwes]}
            ],
            "references": [{"url": r} for r in refs],
        }
    }


def payload(*entries) -> str:
    return json.dumps({"vulnerabilities": list(entries),
                       "totalResults": len(entries)})


def args(**overrides) -> argparse.Namespace:
    values = {"keyword": "log4j", "cve": None, "cpe": None, "exact": False,
              "severity": None, "min_score": None, "network_only": False,
              "days": None, "limit": 20, "api_key": None, "no_cache": True,
              "timeout": 5.0}
    values.update(overrides)
    return argparse.Namespace(**values)


class TestExtractMetric(unittest.TestCase):
    def test_reads_cvss_v31(self):
        severity, score, _, vector = extract_metric(
            cve_entry()["cve"])
        self.assertEqual(severity, "CRITICAL")
        self.assertEqual(score, 10.0)
        self.assertEqual(vector, "NETWORK")

    def test_falls_back_to_v30(self):
        entry = cve_entry(metric_key="cvssMetricV30", severity="HIGH",
                          score=7.5)["cve"]
        severity, score, _, _ = extract_metric(entry)
        self.assertEqual(severity, "HIGH")
        self.assertEqual(score, 7.5)

    def test_falls_back_to_v2_for_old_cves(self):
        entry = cve_entry(metric_key="cvssMetricV2", severity="MEDIUM",
                          score=5.0)["cve"]
        severity, score, _, _ = extract_metric(entry)
        self.assertEqual(severity, "MEDIUM")
        self.assertEqual(score, 5.0)

    def test_prefers_v31_when_several_versions_exist(self):
        entry = cve_entry()["cve"]
        entry["metrics"]["cvssMetricV2"] = [
            {"cvssData": {"baseScore": 4.0, "baseSeverity": "MEDIUM"}}]
        severity, score, _, _ = extract_metric(entry)
        self.assertEqual(severity, "CRITICAL")
        self.assertEqual(score, 10.0)

    def test_missing_metrics_yields_unknown(self):
        severity, score, vector_string, _ = extract_metric({"id": "CVE-X"})
        self.assertEqual(severity, "UNKNOWN")
        self.assertEqual(score, 0.0)
        self.assertEqual(vector_string, "")


class TestParseVulnerability(unittest.TestCase):
    def test_core_fields_are_extracted(self):
        vuln = parse_vulnerability(cve_entry())
        self.assertEqual(vuln.cve_id, "CVE-2021-44228")
        self.assertEqual(vuln.severity, "CRITICAL")
        self.assertEqual(vuln.score, 10.0)
        self.assertEqual(vuln.published, "2021-12-10")

    def test_english_description_is_preferred(self):
        vuln = parse_vulnerability(cve_entry(description="The English one."))
        self.assertEqual(vuln.description, "The English one.")

    def test_cwes_are_collected_without_duplicates(self):
        vuln = parse_vulnerability(
            cve_entry(cwes=("CWE-502", "CWE-502", "CWE-20")))
        self.assertEqual(vuln.cwe, ["CWE-502", "CWE-20"])

    def test_non_cwe_weakness_values_are_ignored(self):
        vuln = parse_vulnerability(cve_entry(cwes=("NVD-CWE-Other", "CWE-20")))
        self.assertEqual(vuln.cwe, ["CWE-20"])

    def test_references_are_capped(self):
        refs = tuple(f"https://example.test/{i}" for i in range(10))
        self.assertEqual(len(parse_vulnerability(cve_entry(refs=refs)).references), 5)

    def test_network_exploitability_flag(self):
        self.assertTrue(parse_vulnerability(cve_entry()).network_exploitable)
        self.assertFalse(parse_vulnerability(
            cve_entry(vector="LOCAL")).network_exploitable)

    def test_missing_fields_do_not_crash(self):
        vuln = parse_vulnerability({"cve": {"id": "CVE-0000-0000"}})
        self.assertEqual(vuln.cve_id, "CVE-0000-0000")
        self.assertEqual(vuln.description, "")


class TestSearch(unittest.TestCase):
    def run_search(self, body: str, **overrides):
        """Run a search against a local fake. Returns (results, recorder)."""
        with http_fake({}, default=(200, {}, body)) as (base, recorder):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                return search(args(**overrides)), recorder

    def test_results_are_returned(self):
        results, _ = self.run_search(payload(cve_entry()))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cve_id, "CVE-2021-44228")

    def test_empty_response_yields_no_results(self):
        results, _ = self.run_search(payload())
        self.assertEqual(results, [])

    def test_results_are_sorted_most_severe_first(self):
        body = payload(cve_entry("CVE-1", "LOW", 2.0),
                       cve_entry("CVE-2", "CRITICAL", 9.8),
                       cve_entry("CVE-3", "MEDIUM", 5.0))
        results, _ = self.run_search(body)
        self.assertEqual([v.severity for v in results],
                         ["CRITICAL", "MEDIUM", "LOW"])

    def test_network_only_filters_local_vulnerabilities(self):
        body = payload(cve_entry("CVE-1", vector="NETWORK"),
                       cve_entry("CVE-2", vector="LOCAL"))
        results, _ = self.run_search(body, network_only=True)
        self.assertEqual([v.cve_id for v in results], ["CVE-1"])

    def test_min_score_filters_low_scores(self):
        body = payload(cve_entry("CVE-1", score=9.8),
                       cve_entry("CVE-2", score=3.1))
        results, _ = self.run_search(body, min_score=7.0)
        self.assertEqual([v.cve_id for v in results], ["CVE-1"])

    def test_limit_caps_the_result_count(self):
        body = payload(*[cve_entry(f"CVE-{i}") for i in range(10)])
        results, _ = self.run_search(body, limit=3)
        self.assertEqual(len(results), 3)

    def test_cve_id_is_sent_as_a_parameter(self):
        _, recorder = self.run_search(payload(cve_entry()),
                                      cve="cve-2021-44228", keyword=None)
        self.assertIn("cveId=CVE-2021-44228", recorder.paths[0])

    def test_keyword_is_sent_as_a_parameter(self):
        _, recorder = self.run_search(payload(), keyword="log4j")
        self.assertIn("keywordSearch=log4j", recorder.paths[0])

    def test_cpe_is_sent_as_a_parameter(self):
        _, recorder = self.run_search(payload(), keyword=None,
                                      cpe="cpe:2.3:a:apache:log4j")
        self.assertIn("cpeName=", recorder.paths[0])

    def test_no_search_term_is_rejected(self):
        with self.assertRaises(ValueError):
            search(args(keyword=None))

    def test_date_range_beyond_the_api_limit_is_rejected_clearly(self):
        """NVD answers an over-wide window with a bare 404; say something useful."""
        with self.assertRaises(ValueError) as ctx:
            search(args(days=MAX_DATE_RANGE_DAYS + 1))
        self.assertIn(str(MAX_DATE_RANGE_DAYS), str(ctx.exception))

    def test_date_range_at_the_limit_is_accepted(self):
        _, recorder = self.run_search(payload(), days=MAX_DATE_RANGE_DAYS)
        self.assertIn("pubStartDate=", recorder.paths[0])


class TestCaching(unittest.TestCase):
    def test_second_identical_query_is_served_from_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            with http_fake({}, default=(200, {}, payload(cve_entry()))) \
                    as (base, recorder):
                with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"), \
                     mock.patch.object(vulnfeed, "CACHE_DIR", tmp):
                    search(args(no_cache=False))
                    search(args(no_cache=False))
                # The second call must not have reached the server.
                self.assertEqual(len(recorder.requests), 1)

    def test_no_cache_always_hits_the_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            with http_fake({}, default=(200, {}, payload())) as (base, recorder):
                with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"), \
                     mock.patch.object(vulnfeed, "CACHE_DIR", tmp):
                    search(args(no_cache=True))
                    search(args(no_cache=True))
                self.assertEqual(len(recorder.requests), 2)

    def test_expired_cache_entry_is_refetched(self):
        with tempfile.TemporaryDirectory() as tmp:
            with http_fake({}, default=(200, {}, payload())) as (base, recorder):
                with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"), \
                     mock.patch.object(vulnfeed, "CACHE_DIR", tmp), \
                     mock.patch.object(vulnfeed, "CACHE_TTL_SECONDS", -1):
                    search(args(no_cache=False))
                    search(args(no_cache=False))
                self.assertEqual(len(recorder.requests), 2)


class TestRateLimitRetry(unittest.TestCase):
    """NVD throttles unauthenticated clients; the retry must be transparent."""

    def setUp(self):
        # query_nvd announces retries on stderr; keep it out of the test log.
        self._quiet = contextlib.redirect_stderr(io.StringIO())
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)

    def sequenced(self, *responses):
        """A fake whose default route returns each response in turn."""
        return http_fake({}, default=list(responses))

    def test_429_is_retried_and_then_succeeds(self):
        with self.sequenced((429, {}, "slow down"),
                            (200, {}, payload(cve_entry()))) as (base, recorder):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"), \
                 mock.patch.object(vulnfeed.time, "sleep", lambda _: None):
                results = search(args())
        self.assertEqual(len(results), 1)
        self.assertEqual(len(recorder.requests), 2)

    def test_403_is_retried(self):
        with self.sequenced((403, {}, "forbidden"),
                            (200, {}, payload())) as (base, recorder):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"), \
                 mock.patch.object(vulnfeed.time, "sleep", lambda _: None):
                search(args())
        self.assertEqual(len(recorder.requests), 2)

    def test_persistent_throttling_eventually_raises(self):
        with self.sequenced((429, {}, "slow down")) as (base, _):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"), \
                 mock.patch.object(vulnfeed.time, "sleep", lambda _: None):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    search(args())
                ctx.exception.close()

    def test_other_http_errors_are_not_retried(self):
        with self.sequenced((404, {}, "not found")) as (base, recorder):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    search(args())
                ctx.exception.close()
        self.assertEqual(len(recorder.requests), 1)

    def test_api_key_is_sent_as_a_header(self):
        with http_fake({}, default=(200, {}, payload())) as (base, recorder):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                search(args(api_key="secret-key"))
        self.assertEqual(recorder.requests[0]["headers"].get("apikey"),
                         "secret-key")


class TestCli(unittest.TestCase):
    def test_high_severity_result_exits_nonzero(self):
        with http_fake({}, default=(200, {}, payload(cve_entry()))) as (base, _):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                code, out = capture_cli(vulnfeed.main,
                                        ["log4j", "--no-cache"])
        self.assertEqual(code, 1)
        self.assertIn("CVE-2021-44228", out)

    def test_low_severity_result_exits_zero(self):
        body = payload(cve_entry("CVE-1", "LOW", 2.0))
        with http_fake({}, default=(200, {}, body)) as (base, _):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                code, _ = capture_cli(vulnfeed.main, ["x", "--no-cache"])
        self.assertEqual(code, 0)

    def test_no_results_is_reported(self):
        with http_fake({}, default=(200, {}, payload())) as (base, _):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                code, out = capture_cli(vulnfeed.main, ["x", "--no-cache"])
        self.assertEqual(code, 0)
        self.assertIn("No vulnerabilities matched", out)

    def test_unreachable_api_reports_cleanly(self):
        with mock.patch.object(vulnfeed, "NVD_API", "http://127.0.0.1:1/cves"):
            code, out = capture_cli(vulnfeed.main,
                                    ["x", "--no-cache", "--timeout", "1"])
        self.assertEqual(code, 1)
        self.assertIn("Could not reach", out)

    def test_verbose_shows_cwe_and_references(self):
        with http_fake({}, default=(200, {}, payload(cve_entry()))) as (base, _):
            with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                _, out = capture_cli(vulnfeed.main, ["x", "--no-cache", "-v"])
        self.assertIn("CWE-502", out)
        self.assertIn("example.test/advisory", out)

    def test_json_output_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = os.path.join(tmp, "r.json")
            with http_fake({}, default=(200, {}, payload(cve_entry()))) \
                    as (base, _):
                with mock.patch.object(vulnfeed, "NVD_API", base + "/cves"):
                    capture_cli(vulnfeed.main,
                                ["x", "--no-cache", "-o", out_file])
            with open(out_file, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertEqual(data[0]["cve_id"], "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
