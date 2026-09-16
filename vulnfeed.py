#!/usr/bin/env python3
"""vulnfeed — CVE lookup and vulnerability triage from the command line.

Queries the NIST National Vulnerability Database for vulnerabilities affecting
a product, a keyword, or a specific CVE, then sorts and filters them the way a
triage session actually needs: worst first, exploitable-from-the-network first,
recent first.

Results are cached locally so repeated triage of the same product does not
re-hit the API.

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = os.path.expanduser("~/.cache/vulnfeed")
CACHE_TTL_SECONDS = 6 * 3600

# The NVD API rejects a publication date range wider than this.
MAX_DATE_RANGE_DAYS = 120

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4,
                  "UNKNOWN": 5}


@dataclass
class Vulnerability:
    cve_id: str
    published: str
    modified: str
    severity: str
    score: float
    vector: str
    attack_vector: str
    description: str
    references: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)

    @property
    def network_exploitable(self) -> bool:
        return self.attack_vector == "NETWORK"


def cache_path(key: str) -> str:
    safe = urllib.parse.quote(key, safe="")
    return os.path.join(CACHE_DIR, f"{safe}.json")


def read_cache(key: str, ttl: int) -> dict | None:
    path = cache_path(key)
    try:
        age = time.time() - os.path.getmtime(path)
        if age > ttl:
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def write_cache(key: str, payload: dict) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        with open(cache_path(key), "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except OSError:
        pass  # a cache failure must never break the query


def query_nvd(params: dict, api_key: str | None, timeout: float,
              use_cache: bool) -> dict:
    """Call the NVD API, honouring the local cache."""
    query = urllib.parse.urlencode(params)
    url = f"{NVD_API}?{query}"

    if use_cache:
        cached = read_cache(query, CACHE_TTL_SECONDS)
        if cached is not None:
            cached["_from_cache"] = True
            return cached

    headers = {"User-Agent": "vulnfeed/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    request = urllib.request.Request(url, headers=headers)
    # NVD rate limits unauthenticated clients to roughly 5 requests per 30s.
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
                write_cache(query, payload)
                return payload
        except urllib.error.HTTPError as exc:
            # An HTTPError holds an open response buffer; release it before
            # retrying or the interpreter leaks a temporary file per attempt.
            retryable = exc.code in (403, 429) and attempt < 2
            if retryable:
                exc.close()
                wait = 6 * (attempt + 1)
                print(f"  Rate limited by NVD; retrying in {wait}s...",
                      file=sys.stderr)
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("exhausted retries against the NVD API")


def extract_metric(cve: dict) -> tuple[str, float, str, str]:
    """Pull the best available CVSS metric, newest version first."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        data = entries[0]
        cvss = data.get("cvssData", {})
        severity = (cvss.get("baseSeverity") or
                    data.get("baseSeverity") or "UNKNOWN").upper()
        return (severity,
                float(cvss.get("baseScore", 0.0)),
                cvss.get("vectorString", ""),
                (cvss.get("attackVector") or data.get("accessVector") or "").upper())
    return "UNKNOWN", 0.0, "", ""


def parse_vulnerability(entry: dict) -> Vulnerability:
    cve = entry.get("cve", entry)
    severity, score, vector, attack_vector = extract_metric(cve)

    description = ""
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", "")
            break

    cwes = []
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    references = [r.get("url", "") for r in cve.get("references", [])][:5]

    return Vulnerability(
        cve_id=cve.get("id", "UNKNOWN"),
        published=(cve.get("published") or "")[:10],
        modified=(cve.get("lastModified") or "")[:10],
        severity=severity,
        score=score,
        vector=vector,
        attack_vector=attack_vector,
        description=description,
        references=[r for r in references if r],
        cwe=cwes,
    )


def search(args) -> list[Vulnerability]:
    params: dict[str, str | int] = {"resultsPerPage": min(args.limit, 200)}

    if args.cve:
        params["cveId"] = args.cve.upper()
    elif args.cpe:
        params["cpeName"] = args.cpe
    elif args.keyword:
        params["keywordSearch"] = args.keyword
        if args.exact:
            params["keywordExactMatch"] = ""
    else:
        raise ValueError("supply a keyword, --cpe, or --cve")

    if args.days:
        # NVD rejects a publication window wider than 120 days with a bare 404,
        # so catch it here and say something useful instead.
        if args.days > MAX_DATE_RANGE_DAYS:
            raise ValueError(
                f"--days cannot exceed {MAX_DATE_RANGE_DAYS}: the NVD API "
                f"limits a publication date range to {MAX_DATE_RANGE_DAYS} "
                f"days. Omit --days to search the full history.")
        since = datetime.now(timezone.utc) - timedelta(days=args.days)
        params["pubStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000")

    if args.severity:
        params["cvssV3Severity"] = args.severity.upper()

    payload = query_nvd(params, args.api_key, args.timeout, not args.no_cache)
    if payload.get("_from_cache"):
        print("  (results served from local cache)\n", file=sys.stderr)

    results = [parse_vulnerability(e) for e in payload.get("vulnerabilities", [])]

    if args.network_only:
        results = [v for v in results if v.network_exploitable]

    if args.min_score:
        results = [v for v in results if v.score >= args.min_score]

    # Worst first, then most recent.
    results.sort(key=lambda v: (SEVERITY_ORDER.get(v.severity, 5),
                                -v.score, v.published), reverse=False)
    return results[:args.limit]


def print_results(results: list[Vulnerability], verbose: bool) -> None:
    if not results:
        print("\n  No vulnerabilities matched.\n")
        return

    print(f"\n  {len(results)} result(s), most severe first:\n")
    for vuln in results:
        flag = " [network]" if vuln.network_exploitable else ""
        print(f"  {vuln.cve_id}  {vuln.severity} {vuln.score:.1f}{flag}"
              f"   published {vuln.published}")
        wrapped = textwrap.fill(vuln.description, width=88,
                                initial_indent="      ",
                                subsequent_indent="      ")
        print(wrapped[:900])
        if verbose:
            if vuln.cwe:
                print(f"      CWE     : {', '.join(vuln.cwe)}")
            if vuln.vector:
                print(f"      Vector  : {vuln.vector}")
            for url in vuln.references[:3]:
                print(f"      Ref     : {url}")
        print()

    counts: dict[str, int] = {}
    for vuln in results:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
    summary = "  ".join(
        f"{sev.lower()}: {counts[sev]}"
        for sev in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 5)))
    print(f"  Summary: {summary}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CVE lookup and vulnerability triage from the command line.",
        epilog="Examples:\n"
               "  vulnfeed.py openssh --days 365 --severity HIGH\n"
               "  vulnfeed.py --cve CVE-2021-44228 -v\n"
               "  vulnfeed.py --cpe 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("keyword", nargs="?", help="product or keyword to search")
    parser.add_argument("--cve", help="look up one CVE by id")
    parser.add_argument("--cpe", help="search by exact CPE 2.3 name")
    parser.add_argument("--exact", action="store_true",
                        help="require an exact keyword match")
    parser.add_argument("-s", "--severity",
                        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="filter by CVSS v3 severity")
    parser.add_argument("--min-score", type=float,
                        help="filter by minimum CVSS base score")
    parser.add_argument("--network-only", action="store_true",
                        help="only vulnerabilities exploitable over the network")
    parser.add_argument("--days", type=int,
                        help="only CVEs published in the last N days")
    parser.add_argument("-n", "--limit", type=int, default=20,
                        help="maximum results (default 20)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show CWE, CVSS vector, and references")
    parser.add_argument("-o", "--output", help="write results as JSON")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                        help="NVD API key (or set NVD_API_KEY) for higher rate limits")
    parser.add_argument("--no-cache", action="store_true",
                        help="bypass the local result cache")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="request timeout in seconds (default 30)")
    args = parser.parse_args(argv)

    try:
        results = search(args)
    except ValueError as exc:
        parser.error(str(exc))
    except urllib.error.HTTPError as exc:
        with exc:  # release the response buffer
            print(f"NVD API error {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError, RuntimeError) as exc:
        print(f"Could not reach the NVD API: {exc}", file=sys.stderr)
        return 1

    print_results(results, args.verbose)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump([asdict(v) for v in results], fh, indent=2)
        print(f"  Written to {args.output}\n")

    # Non-zero when something critical or high turned up, for CI gating.
    return 1 if any(v.severity in ("CRITICAL", "HIGH") for v in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
