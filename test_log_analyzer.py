"""Unit tests for logwatch (log_analyzer).

Run with:  python3 -m pytest -q
"""

import json

import pytest

import log_analyzer as la


VALID_LINE = (
    '192.0.2.10 - - [30/Sep/2026:21:15:04 +0200] '
    '"GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
)
COMMON_LINE = (
    '192.0.2.11 - - [30/Sep/2026:21:16:00 +0200] '
    '"GET /a HTTP/1.1" 404 0'  # no referer/agent (Common Log Format)
)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def test_parse_valid_combined_line():
    entry = la.parse_line(VALID_LINE)
    assert entry is not None
    assert entry.ip == "192.0.2.10"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.status == 200
    assert entry.size == 512


def test_parse_common_log_format_without_agent():
    entry = la.parse_line(COMMON_LINE)
    assert entry is not None
    assert entry.status == 404
    assert entry.size == 0


@pytest.mark.parametrize("bad", ["", "   ", "garbage line", "not a log at all"])
def test_parse_malformed_returns_none(bad):
    assert la.parse_line(bad) is None


# ---------------------------------------------------------------------------
# Signature matching
# ---------------------------------------------------------------------------
def test_sqli_signatures():
    sqli, _ = la.match_signatures("/products?id=1+UNION+SELECT+pw+FROM+users--")
    assert sqli
    sqli2, _ = la.match_signatures("/search?q=%27%20OR%201%3D1--")
    assert sqli2


def test_traversal_signatures():
    _, trav = la.match_signatures("/download?file=../../../../etc/passwd")
    assert trav
    _, trav2 = la.match_signatures("/x?p=%2e%2e%2fetc%2fpasswd")
    assert trav2


def test_clean_path_has_no_hits():
    sqli, trav = la.match_signatures("/products?id=12")
    assert not sqli and not trav


def test_plus_is_decoded_as_space():
    sqli, _ = la.match_signatures("/login?id=1'+OR+'1'='1")
    assert sqli  # '+' must decode to space for this to match


# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------
def _entry(ip, status=200, path="/"):
    return la.LogEntry(ip=ip, time="-", method="GET", path=path,
                       status=status, size=0)


def test_brute_force_threshold():
    az = la.LogAnalyzer(brute_threshold=5)
    for _ in range(5):
        az.feed(_entry("10.0.0.1", status=401))
    findings = az.findings()
    assert len(findings) == 1
    assert "brute-force" in findings[0].reasons[0]


def test_below_brute_threshold_not_flagged():
    az = la.LogAnalyzer(brute_threshold=5)
    for _ in range(4):
        az.feed(_entry("10.0.0.1", status=401))
    assert az.findings() == []


def test_scanning_threshold():
    az = la.LogAnalyzer(scan_threshold=20)
    for i in range(20):
        az.feed(_entry("10.0.0.2", status=404, path=f"/missing{i}"))
    findings = az.findings()
    assert findings and "scanning" in findings[0].reasons[0]


def test_sqli_flagged_immediately():
    az = la.LogAnalyzer()
    az.feed(_entry("10.0.0.3", status=200, path="/x?id=1+OR+1=1--"))
    findings = az.findings()
    assert findings and any("SQL" in r for r in findings[0].reasons)


def test_findings_sorted_by_score():
    az = la.LogAnalyzer(brute_threshold=3)
    # High-score IP: many auth failures.
    for _ in range(10):
        az.feed(_entry("10.0.0.9", status=403))
    # Lower-score IP: just at the brute threshold.
    for _ in range(3):
        az.feed(_entry("10.0.0.8", status=401))
    findings = az.findings()
    assert [f.ip for f in findings] == ["10.0.0.9", "10.0.0.8"]


# ---------------------------------------------------------------------------
# End-to-end on a temp file
# ---------------------------------------------------------------------------
def test_analyze_file_and_json(tmp_path):
    log = tmp_path / "access.log"
    lines = [VALID_LINE] * 3
    lines += [
        f'5.5.5.5 - - [t] "POST /login HTTP/1.1" 401 0 "-" "x"'
        for _ in range(6)
    ]
    log.write_text("\n".join(lines) + "\n")

    az = la.LogAnalyzer(brute_threshold=5)
    az.analyze_file(str(log))
    findings = az.findings()
    assert az.parsed_lines == 9
    assert any(f.ip == "5.5.5.5" for f in findings)

    out = tmp_path / "out.json"
    la.write_json(az, findings, str(out))
    doc = json.loads(out.read_text())
    assert doc["summary"]["suspicious_ips"] == len(findings)
    assert doc["findings"][0]["ip"] == "5.5.5.5"
