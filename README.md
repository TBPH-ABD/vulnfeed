# vulnfeed

CVE lookup and vulnerability triage from the command line. Queries the NIST
National Vulnerability Database and sorts results the way a triage session
actually needs them: **worst first, network-exploitable flagged, recent first**.

## Why

Browsing the NVD web interface is fine for one CVE. It is painful when you are
working through "what is currently known against every version of this product
in our estate". `vulnfeed` turns that into one command with filters that match
how you prioritise.

## Features

- Search by **keyword**, **exact CPE 2.3 name**, or a **specific CVE id**
- Filter by **CVSS v3 severity**, **minimum base score**, and **publication window**
- `--network-only` narrows to vulnerabilities with attack vector `NETWORK` —
  the ones reachable without a foothold
- Reads CVSS **v3.1 → v3.0 → v2** in that order, so old CVEs still score
- Shows **CWE classes** and **references** in verbose mode
- **Local cache** (6 hours) so repeated triage does not re-hit the API
- **Rate-limit aware** — backs off and retries on 403/429

## Requirements

Python 3.10 or newer. No packages to install.

An NVD API key is optional but recommended; it raises the rate limit
considerably. Pass `--api-key` or set `NVD_API_KEY` in your environment.
Keys are free from <https://nvd.nist.gov/developers/request-an-api-key>.

## Usage

```bash
# Look up one CVE in full detail
python3 vulnfeed.py --cve CVE-2021-44228 -v

# What has been published against OpenSSH in the last 60 days?
python3 vulnfeed.py openssh --days 60

# Only critical, network-reachable issues, saved for the report
python3 vulnfeed.py "apache http server" -s CRITICAL --network-only -o findings.json

# Pin the query to an exact product version
python3 vulnfeed.py --cpe 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `--cve` | Look up one CVE by id | — |
| `--cpe` | Search by exact CPE 2.3 name | — |
| `--exact` | Require an exact keyword match | off |
| `-s`, `--severity` | Filter by CVSS v3 severity | — |
| `--min-score` | Filter by minimum CVSS base score | — |
| `--network-only` | Only network-exploitable vulnerabilities | off |
| `--days` | Only CVEs published in the last N days (max 120) | — |
| `-n`, `--limit` | Maximum results | `20` |
| `-v`, `--verbose` | Show CWE, CVSS vector, and references | off |
| `-o`, `--output` | Write results as JSON | — |
| `--api-key` | NVD API key (or `NVD_API_KEY`) | — |
| `--no-cache` | Bypass the local result cache | off |

> The NVD API rejects a publication window wider than 120 days. `vulnfeed`
> validates this up front and tells you, rather than passing through the bare
> `404` the API returns.

## Example

```
  1 result(s), most severe first:

  CVE-2021-44228  CRITICAL 10.0 [network]   published 2021-12-10
      Apache Log4j2 2.0-beta9 through 2.15.0 ... An attacker who can control log
      messages or log message parameters can execute arbitrary code loaded from
      LDAP servers when message lookup substitution is enabled.
      CWE     : CWE-20, CWE-400, CWE-502, CWE-917
      Vector  : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
      Ref     : http://packetstormsecurity.com/files/165225/...

  Summary: critical: 1
```

## Use in CI

Exits `1` when any critical or high severity CVE is in the result set, so it can
fail a pipeline that depends on a vulnerable component:

```yaml
- name: Check dependency for known CVEs
  run: python3 vulnfeed.py --cpe "$CPE_NAME" -s HIGH --days 90
```

## License

MIT — see [LICENSE](LICENSE). Vulnerability data is provided by the NVD.
