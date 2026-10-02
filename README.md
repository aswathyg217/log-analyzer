# logwatch — Web Access-Log Analyzer for Incident Response

A command-line tool written in Python 3.10+ that parses an Apache/Nginx access
log and flags signs of attack, then prints a **ranked summary of suspicious
source IPs**. Built for the log-analysis / incident-response category of the
assignment.

It detects four common patterns:

| Detection | How it's found |
| --- | --- |
| **Brute-force login attempts** | Many `401`/`403` responses from one IP |
| **SQL-injection probes** | SQLi signatures in the (URL-decoded) request path |
| **Path-traversal probes** | `../`, encoded variants, `/etc/passwd`, `boot.ini` |
| **Scanning / enumeration** | One IP generating many `404`s |

Each suspicious IP is given a **severity score** so the highest-risk source
sorts to the top of the report — the way a SOC analyst would triage.

> ⚠️ **Ethical & legal use.** Analyse only logs you are authorised to handle.
> Access logs contain IP addresses and request data that may be **personal data
> under the GDPR** — handle and store them accordingly.

---

## Features

- **Robust parser** for the Common and Combined Log Formats (the referrer and
  user-agent fields are optional). Malformed lines are skipped, not fatal.
- **URL-decoding** of the request path (both `%XX` escapes and `+` as space) so
  encoded payloads still match the signatures.
- **Tunable thresholds** for brute-force and scanning via CLI flags.
- **JSON export** of all findings + scan metadata for a SIEM or ticket.
- **No third-party dependencies** — pure standard library.
- **Clean error handling** — missing files and bad input produce friendly
  messages, never a raw stack trace.
- Ships with a **sample `access.log`** (and the generator that made it) so the
  tool always has something to demonstrate on.

---

## Prerequisites

- **Python 3.10 or newer.** No packages to install.

```bash
python3 --version   # 3.10+
```

---

## Installation

```bash
git clone https://github.com/<your-username>/logwatch.git
cd logwatch
chmod +x log_analyzer.py     # optional, Linux/macOS
```

---

## Usage

```
python3 log_analyzer.py LOGFILE [options]
```

| Option | Description |
| --- | --- |
| `logfile` | Path to the access-log file (positional, required) |
| `-b`, `--brute-threshold` | Auth failures (401/403) from one IP to flag (default: 5) |
| `-s`, `--scan-threshold` | 404s from one IP to flag as scanning (default: 20) |
| `-o`, `--output FILE` | Write findings to `FILE` as JSON |
| `-h`, `--help` | Show the help menu and exit |

### Examples

```bash
# Analyse the bundled sample log
python3 log_analyzer.py access.log

# Be stricter about brute-force, save the findings as JSON
python3 log_analyzer.py access.log --brute-threshold 3 -o report.json

# Analyse a real Nginx log
python3 log_analyzer.py /var/log/nginx/access.log

# Regenerate the sample log (optional)
python3 make_sample_log.py
```

---

## Sample output

```
================================================================
  Access-log analysis report
================================================================
Lines read      : 274
Lines parsed    : 274
Unique IPs      : 42
Suspicious IPs  : 4
----------------------------------------------------------------
#1  198.51.100.23   (score 36)
    requests=18  auth_fail=18  404=0
    [!] brute-force: 18 auth failures (401/403)
----------------------------------------------------------------
#2  198.51.100.77   (score 35)
    requests=7  auth_fail=0  404=0
    [!] SQL injection: 7 suspicious request(s)
        SQLi> /products?id=1+UNION+SELECT+username,password+FROM+users--
        SQLi> /search?q=%27%20OR%201%3D1--
        SQLi> /products?id=1;DROP+TABLE+users--
----------------------------------------------------------------
#3  198.51.100.5   (score 25)
    requests=25  auth_fail=0  404=25
    [!] scanning: 25 not-found (404) responses
----------------------------------------------------------------
#4  198.51.100.200   (score 20)
    requests=4  auth_fail=2  404=2
    [!] path traversal: 4 suspicious request(s)
        PATH> /download?file=../../../../etc/passwd
        PATH> /view?page=../../windows/boot.ini
        PATH> /assets/..%2f..%2f..%2fetc%2fpasswd
----------------------------------------------------------------
```

### JSON output (`-o report.json`)

```json
{
  "summary": {
    "lines_read": 274,
    "lines_parsed": 274,
    "unique_ips": 42,
    "suspicious_ips": 4
  },
  "findings": [
    {
      "ip": "198.51.100.23",
      "total_requests": 18,
      "auth_failures": 18,
      "not_found": 0,
      "sqli_hits": [],
      "traversal_hits": [],
      "reasons": ["brute-force: 18 auth failures (401/403)"],
      "score": 36
    }
  ]
}
```

---

## How detection works

1. **Parse** — each line is matched against a regex for the Combined Log Format;
   the IP, method, path, and status code are extracted. Unparseable lines are
   counted but skipped.
2. **Tally per IP** — for every IP the tool counts total requests, `401/403`
   auth failures, and `404`s, and records any request path that matches an SQLi
   or path-traversal signature (after URL-decoding).
3. **Score & rank** — thresholds turn tallies into findings. Signature hits are
   weighted most heavily (they're high-confidence), brute-force next, scanning
   last. IPs are sorted by score so the analyst sees the worst offender first.

**Design note / limitations (by design):** this is a *signature- and
threshold-based* detector, so it can raise false positives (a legitimate
security scanner, a user fat-fingering a password) and miss novel or heavily
obfuscated attacks. It is a triage aid, not a replacement for a tuned WAF or
SIEM. These trade-offs are discussed in the accompanying reflection report.

---

## Running the tests

```bash
pip install pytest
python3 -m pytest -q
```

The suite covers log-line parsing (valid, Common-format, and malformed lines),
signature matching (including `+`-as-space decoding), each detection threshold,
score-based ranking, and end-to-end JSON output.

---

## Project layout

```
logwatch/
├── log_analyzer.py        # the analyzer (CLI entry point)
├── test_log_analyzer.py   # pytest suite
├── make_sample_log.py     # generator for the sample log
├── access.log             # sample log with embedded attacks
├── requirements.txt       # (no runtime deps; pytest for tests)
├── README.md              # this file
└── reflection.pdf         # defensive reflection report
```

---

## License

Provided for educational use as part of the *Python / Bash / PowerShell for
Cybersecurity* course.
