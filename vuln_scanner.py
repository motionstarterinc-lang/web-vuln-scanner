"""
vuln_scanner.py

A lightweight, defensive web security scanner. It checks a website's own
public configuration for common weaknesses -- it does not attack or exploit
anything. Only run this against sites you own or have explicit permission
to test.

Author: David Oladimejij
"""

import sys
import requests


SECURITY_HEADERS = [
  "Content-Security-Policy",
  "Strict-Transport-Security",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Referrer-Policy",
  "Permissions-Policy",
]

EXPOSED_PATHS = [
  "/.git/config",
  "/.env",
  "/backup.zip",
  "/.DS_Store",
  "/wp-config.php.bak",
]


def normalize_url(target):
  has_scheme = target.startswith("http://") or target.startswith("https://")
  result = target if has_scheme else "https://" + target
  return result.rstrip("/")


def check_https_enforced(target):
  http_url = target.replace("https://", "http://")
  response = requests.get(http_url, timeout=5, allow_redirects=True)
  enforced = response.url.startswith("https://")
  print("HTTPS enforced: " + str(enforced))
  return enforced


def check_security_headers(target):
  response = requests.get(target, timeout=5)
  headers = response.headers
  print("")
  print("Security headers:")
  missing = [h for h in SECURITY_HEADERS if h not in headers]
  present = [h for h in SECURITY_HEADERS if h in headers]
  for header in present:
    print("  " + header + ": present")
  for header in missing:
    print("  " + header + ": MISSING")
  return missing


def check_cookie_flags(target):
  response = requests.get(target, timeout=5)
  cookies = response.headers.get("Set-Cookie", "")
  print("")
  print("Cookie flags:")
  print("  Secure flag present: " + str("Secure" in cookies))
  print("  HttpOnly flag present: " + str("HttpOnly" in cookies))
  print("  SameSite flag present: " + str("SameSite" in cookies))


def check_server_banner(target):
  response = requests.get(target, timeout=5)
  server = response.headers.get("Server", "not disclosed")
  powered_by = response.headers.get("X-Powered-By", "not disclosed")
  print("")
  print("Server banner disclosure:")
  print("  Server: " + server)
  print("  X-Powered-By: " + powered_by)


def check_exposed_paths(target):
  print("")
  print("Common exposed file check:")
  for path in EXPOSED_PATHS:
    url = target + path
    response = requests.get(url, timeout=5)
    found = response.status_code == 200
    status = "FOUND (status 200)" if found else "not found"
    print("  " + path + ": " + status)


def run_scan(target):
  target = normalize_url(target)
  print("Scanning: " + target)
  print("=" * 50)
  check_https_enforced(target)
  check_security_headers(target)
  check_cookie_flags(target)
  check_server_banner(target)
  check_exposed_paths(target)
  print("")
  print("Scan complete. This is a configuration check only, not proof of exploitability.")


if __name__ == "__main__":
  has_arg = len(sys.argv) >= 2
  target_arg = sys.argv[1] if has_arg else None
  if not has_arg:
    print("Usage: python vuln_scanner.py <target-domain>")
    print("Example: python vuln_scanner.py example.com")
    sys.exit(1)
  run_scan(target_arg)
    
