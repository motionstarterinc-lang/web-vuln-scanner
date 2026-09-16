Web Vulnerability Scanner

A lightweight, defensive Python scanner that checks a website's own public configuration for common security weaknesses. It does not attack or exploit anything, it only inspects what is already publicly visible.

What it checks:
Whether HTTPS is enforced. Missing or present security headers (Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy). Insecure cookie flags (missing Secure, HttpOnly, SameSite). Server and technology banner disclosure. Common exposed files (.git/config, .env, backup files).

Why:
Built to apply the common vulnerability categories (missing headers, exposed configs, weak cookie flags) in a safe, defensive, read-only way, instead of just reading about them.

Requirements:
Python 3. Install dependencies with: pip install -r requirements.txt

Usage:
Run "python vuln_scanner.py <target-domain>" from the command line. Example: python vuln_scanner.py example.com

Important: Only run this against websites you own or have explicit written permission to test. Running it against sites you do not control without authorization may be illegal. This tool performs read-only checks against public configuration; it does not attempt to exploit, bypass authentication, or access anything private.

Author: David Oladimejij, IT student at Towson University.
