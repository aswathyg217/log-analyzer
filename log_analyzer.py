#!/usr/bin/env python3
"""logwatch - a web access-log analyzer for incident response.

Parses an Apache/Nginx access log (Common or Combined Log Format) and flags
suspicious activity:

* **Brute-force attempts** - many 401/403 responses from a single IP.
* **SQL-injection probes** - SQLi signatures in the request path/query.
* **Path-traversal probes** - ``../`` and encoded variants.
* **Scanning / enumeration** - a single IP generating many 404s.

It prints a ranked summary of suspicious source IPs and can export the full
findings to JSON for a SIEM or ticket.

Author : Aswathy
Course : Python / Bash / PowerShell for Cybersecurity
Python  : 3.10+

Ethical use notice
------------------
Analyse only logs you are authorised to handle. Access logs contain IP
addresses and request data that may be personal data under the GDPR; treat
them accordingly.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
# Combined Log Format:
#   %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
# Example:
#   192.0.2.10 - - [30/Sep/2026:21:15:04 +0200] "GET /index.html HTTP/1.1" 200
#   512 "-" "Mozilla/5.0"
# The trailing referrer/user-agent fields are optional (Common Log Format
# omits them), so they are captured non-greedily and may be absent.
_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+\S+\s+'                       # ident, authuser (usually "-")
    r'\[(?P<time>[^\]]+)\]\s+'            # timestamp
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Signatures for SQL injection (case-insensitive, matched against the URL-
# decoded request path). These are intentionally readable rather than
# exhaustive; a production WAF would use a far larger, tuned ruleset.
_SQLI_SIGNATURES = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"union\s+select",
        r"select.+from",
        r"insert\s+into",
        r"drop\s+table",
        r"or\s+1\s*=\s*1",
        r"'\s*or\s*'",
        r"--\s*$",
        r";\s*--",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"information_schema",
        r"xp_cmdshell",
    )
]

# Path-traversal signatures (raw and percent-encoded forms of "../").
_TRAVERSAL_SIGNATURES = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"/etc/passwd",
        r"boot\.ini",
    )
]

BRUTE_FORCE_STATUSES = {401, 403}


@dataclass
class LogEntry:
    """One successfully parsed access-log line."""

    ip: str
    time: str
    method: str
    path: str
    status: int
    size: int


@dataclass
class IPReport:
    """Accumulated suspicious activity for a single source IP."""

    ip: str
    total_requests: int = 0
    auth_failures: int = 0
    not_found: int = 0
    sqli_hits: list[str] = field(default_factory=list)
    traversal_hits: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    score: int = 0


def _url_decode(value: str) -> str:
    """Best-effort percent-decoding so encoded payloads still match.

    A minimal decoder is used (rather than urllib) so that a malformed escape
    sequence never raises - attackers deliberately send broken encodings.

    Args:
        value: The raw request path.

    Returns:
        The decoded string, lower-cased for signature matching.
    """
    def _replace(match: re.Match) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    # In query strings '+' encodes a space; decode it so payloads like
    # "1'+OR+'1'='1" still match the signatures.
    decoded = re.sub(r"%([0-9a-fA-F]{2})", _replace, value.replace("+", " "))
    return decoded


def parse_line(line: str) -> LogEntry | None:
    """Parse a single access-log line.

    Args:
        line: A raw line from the log file.

    Returns:
        A :class:`LogEntry`, or ``None`` if the line does not match the
        expected format (blank lines, partial writes, unrelated formats).
    """
    match = _LOG_PATTERN.match(line.strip())
    if not match:
        return None
    try:
        status = int(match.group("status"))
    except ValueError:
        return None
    size_raw = match.group("size")
    size = int(size_raw) if size_raw.isdigit() else 0
    return LogEntry(
        ip=match.group("ip"),
        time=match.group("time"),
        method=match.group("method"),
        path=match.group("path"),
        status=status,
        size=size,
    )


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def match_signatures(path: str) -> tuple[list[str], list[str]]:
    """Check a request path against SQLi and traversal signatures.

    Args:
        path: The raw request path (may be percent-encoded).

    Returns:
        A tuple ``(sqli_matches, traversal_matches)`` of the signature
        patterns that fired.
    """
    decoded = _url_decode(path)
    sqli = [sig.pattern for sig in _SQLI_SIGNATURES if sig.search(decoded)]
    traversal = [
        sig.pattern for sig in _TRAVERSAL_SIGNATURES if sig.search(decoded)
    ]
    return sqli, traversal


class LogAnalyzer:
    """Aggregates per-IP suspicious activity and scores it.

    Attributes:
        brute_threshold: Auth failures from one IP before it is flagged.
        scan_threshold: 404s from one IP before it is flagged as scanning.
    """

    def __init__(self, brute_threshold: int = 5, scan_threshold: int = 20) -> None:
        self.brute_threshold = brute_threshold
        self.scan_threshold = scan_threshold
        self._reports: dict[str, IPReport] = {}
        self.total_lines = 0
        self.parsed_lines = 0

    def _report_for(self, ip: str) -> IPReport:
        """Return (creating if needed) the IPReport for an address."""
        if ip not in self._reports:
            self._reports[ip] = IPReport(ip=ip)
        return self._reports[ip]

    def feed(self, entry: LogEntry) -> None:
        """Incorporate one parsed log entry into the per-IP tallies."""
        report = self._report_for(entry.ip)
        report.total_requests += 1

        if entry.status in BRUTE_FORCE_STATUSES:
            report.auth_failures += 1
        if entry.status == 404:
            report.not_found += 1

        sqli, traversal = match_signatures(entry.path)
        # Keep a bounded sample of offending paths for the report.
        for hit in sqli:
            if entry.path not in report.sqli_hits:
                report.sqli_hits.append(entry.path)
        for hit in traversal:
            if entry.path not in report.traversal_hits:
                report.traversal_hits.append(entry.path)

    def analyze_file(self, path: str) -> None:
        """Parse and analyse an entire log file.

        Args:
            path: Path to the access-log file.

        Raises:
            OSError: If the file cannot be opened (handled by the caller).
        """
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                self.total_lines += 1
                entry = parse_line(line)
                if entry is None:
                    continue
                self.parsed_lines += 1
                self.feed(entry)

    def findings(self) -> list[IPReport]:
        """Evaluate thresholds and return suspicious IPs, most severe first.

        Returns:
            A list of :class:`IPReport` objects that tripped at least one
            detection rule, sorted by descending score.
        """
        suspicious: list[IPReport] = []
        for report in self._reports.values():
            report.reasons = []
            report.score = 0

            if report.auth_failures >= self.brute_threshold:
                report.reasons.append(
                    f"brute-force: {report.auth_failures} auth failures "
                    f"(401/403)"
                )
                report.score += report.auth_failures * 2
            if report.sqli_hits:
                report.reasons.append(
                    f"SQL injection: {len(report.sqli_hits)} suspicious "
                    f"request(s)"
                )
                report.score += len(report.sqli_hits) * 5
            if report.traversal_hits:
                report.reasons.append(
                    f"path traversal: {len(report.traversal_hits)} "
                    f"suspicious request(s)"
                )
                report.score += len(report.traversal_hits) * 5
            if report.not_found >= self.scan_threshold:
                report.reasons.append(
                    f"scanning: {report.not_found} not-found (404) responses"
                )
                report.score += report.not_found

            if report.reasons:
                suspicious.append(report)

        suspicious.sort(key=lambda r: r.score, reverse=True)
        return suspicious


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(analyzer: LogAnalyzer, findings: list[IPReport]) -> None:
    """Print a human-readable summary of the findings to stdout."""
    print("=" * 64)
    print("  Access-log analysis report")
    print("=" * 64)
    print(
        f"Lines read      : {analyzer.total_lines}\n"
        f"Lines parsed    : {analyzer.parsed_lines}\n"
        f"Unique IPs      : {len(analyzer._reports)}\n"
        f"Suspicious IPs  : {len(findings)}"
    )
    if not findings:
        print("\nNo suspicious activity detected.")
        return

    for rank, report in enumerate(findings, start=1):
        print("-" * 64)
        print(f"#{rank}  {report.ip}   (score {report.score})")
        print(
            f"    requests={report.total_requests}  "
            f"auth_fail={report.auth_failures}  404={report.not_found}"
        )
        for reason in report.reasons:
            print(f"    [!] {reason}")
        for sample in report.sqli_hits[:3]:
            print(f"        SQLi> {sample}")
        for sample in report.traversal_hits[:3]:
            print(f"        PATH> {sample}")
    print("-" * 64)


def write_json(analyzer: LogAnalyzer, findings: list[IPReport], path: str) -> None:
    """Write findings and scan metadata to a JSON file.

    Args:
        analyzer: The analyzer holding scan statistics.
        findings: The suspicious IP reports.
        path: Destination file path.

    Raises:
        OSError: If the file cannot be written (handled by the caller).
    """
    document = {
        "summary": {
            "lines_read": analyzer.total_lines,
            "lines_parsed": analyzer.parsed_lines,
            "unique_ips": len(analyzer._reports),
            "suspicious_ips": len(findings),
        },
        "findings": [asdict(report) for report in findings],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse command-line parser."""
    parser = argparse.ArgumentParser(
        prog="logwatch",
        description="Analyse an Apache/Nginx access log for signs of attack.",
        epilog="Example: logwatch access.log --brute-threshold 5 -o report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("logfile", help="path to the access-log file")
    parser.add_argument(
        "-b", "--brute-threshold", type=int, default=5,
        help="auth failures (401/403) from one IP to flag (default: 5)",
    )
    parser.add_argument(
        "-s", "--scan-threshold", type=int, default=20,
        help="404s from one IP to flag as scanning (default: 20)",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE", help="write findings to FILE as JSON"
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate threshold arguments.

    Raises:
        ValueError: If a threshold is below 1.
    """
    if args.brute_threshold < 1:
        raise ValueError("brute-threshold must be at least 1")
    if args.scan_threshold < 1:
        raise ValueError("scan-threshold must be at least 1")


def main(argv: list[str] | None = None) -> int:
    """Program entry point.

    Parses arguments, runs the analysis, and converts errors into clean
    messages on stderr (never a raw stack trace).

    Args:
        argv: Optional argument vector (defaults to ``sys.argv``).

    Returns:
        Process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_args(args)
        analyzer = LogAnalyzer(
            brute_threshold=args.brute_threshold,
            scan_threshold=args.scan_threshold,
        )
        analyzer.analyze_file(args.logfile)
        findings = analyzer.findings()
        print_report(analyzer, findings)
        if args.output:
            write_json(analyzer, findings, args.output)
            print(f"\n[*] Findings written to {args.output}")
        return 0
    except FileNotFoundError:
        print(f"[!] Log file not found: {args.logfile}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"[!] Invalid input: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[!] File error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
