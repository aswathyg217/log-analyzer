#!/usr/bin/env python3
"""Generate a realistic sample access.log with embedded attack patterns."""

import random
from datetime import datetime, timedelta

random.seed(42)

UA = ('"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/120 Safari/537.36"')
BOT_UA = '"sqlmap/1.7#stable (http://sqlmap.org)"'

start = datetime(2026, 9, 30, 20, 0, 0)
lines = []
t = [start]


def stamp():
    t[0] += timedelta(seconds=random.randint(1, 4))
    return t[0].strftime("%d/%b/%Y:%H:%M:%S +0200")


def line(ip, method, path, status, size, ua=UA):
    return f'{ip} - - [{stamp()}] "{method} {path} HTTP/1.1" {status} {size} "-" {ua}'


NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/products?id=12",
    "/static/style.css", "/static/app.js", "/images/logo.png",
    "/blog/2026/security-tips", "/contact", "/favicon.ico", "/api/health",
]
NORMAL_IPS = [f"203.0.113.{i}" for i in range(2, 40)]

# 1. Normal background traffic
for _ in range(220):
    ip = random.choice(NORMAL_IPS)
    path = random.choice(NORMAL_PATHS)
    status = random.choices([200, 200, 200, 304, 302, 404], weights=[6, 6, 6, 2, 1, 1])[0]
    lines.append(line(ip, random.choice(["GET", "GET", "GET", "POST"]), path,
                      status, random.randint(200, 5000)))

# 2. Brute-force attack: one IP hammering /login with 401/403
attacker_bf = "198.51.100.23"
for _ in range(18):
    lines.append(line(attacker_bf, "POST", "/login", random.choice([401, 401, 403]),
                      0))

# 3. SQL-injection probes from another IP (sqlmap-style)
attacker_sqli = "198.51.100.77"
sqli_paths = [
    "/products?id=1'+OR+'1'='1",
    "/products?id=1+UNION+SELECT+username,password+FROM+users--",
    "/search?q=%27%20OR%201%3D1--",
    "/products?id=1;DROP+TABLE+users--",
    "/login?user=admin'--",
    "/api/item?id=1+AND+SLEEP(5)",
    "/products?id=-1+UNION+SELECT+1,2,3,information_schema.tables",
]
for p in sqli_paths:
    lines.append(line(attacker_sqli, "GET", p, random.choice([200, 500]),
                      random.randint(0, 900), ua=BOT_UA))

# 4. Path-traversal probes
attacker_lfi = "198.51.100.200"
lfi_paths = [
    "/download?file=../../../../etc/passwd",
    "/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/view?page=../../windows/boot.ini",
    "/assets/..%2f..%2f..%2fetc%2fpasswd",
]
for p in lfi_paths:
    lines.append(line(attacker_lfi, "GET", p, random.choice([200, 403, 404]),
                      random.randint(0, 400)))

# 5. Directory/endpoint scanning: one IP generating many 404s
scanner = "198.51.100.5"
scan_paths = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git/config",
    "/backup.zip", "/config.php.bak", "/administrator", "/server-status",
    "/api/v1/users", "/old", "/test", "/staging", "/.aws/credentials",
    "/wp-login.php", "/xmlrpc.php", "/vendor/phpunit", "/.ssh/id_rsa",
    "/db.sql", "/dump.sql", "/shell.php", "/cmd.php", "/uploads/",
    "/console", "/debug",
]
for p in scan_paths:
    lines.append(line(scanner, "GET", p, 404, 0))

# Shuffle the attack lines into a plausible interleaving with normal traffic,
# but keep a rough chronological feel by sorting on the embedded timestamp.
random.shuffle(lines)

with open("access.log", "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")

print(f"wrote access.log with {len(lines)} lines")
