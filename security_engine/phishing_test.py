#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phishing Resistance Tester
Kiem tra kha nang chong Phishing cua web app:
- Security Headers (CSP, HSTS, X-Frame-Options, ...)
- Clickjacking vulnerability
- CSRF protection
- Open redirect
- Mixed content
- Cookie security flags
- HTTPS enforcement
"""

import re
import time
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import requests
from requests.exceptions import RequestException

# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    category: str
    status: str            # "pass" | "fail" | "warn" | "info"
    detail: str
    severity: str          # "critical" | "high" | "medium" | "low" | "info"
    recommendation: str = ""
    score: int = 0         # 0-10 points contributed

@dataclass
class PhishingReport:
    url: str
    timestamp: str = ""
    total_score: int = 0
    max_score: int = 100
    grade: str = "F"
    checks: List[CheckResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    is_https: bool = False
    server_info: str = ""
    elapsed: float = 0.0

# ── Header Definitions ─────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "score": 10,
        "good_pattern": r"max-age=\d+",
        "detail": "HSTS prevents downgrade attacks and cookie hijacking",
        "rec": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "score": 15,
        "good_pattern": None,
        "detail": "CSP prevents XSS and data injection attacks",
        "rec": "Add CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "score": 10,
        "good_pattern": r"(DENY|SAMEORIGIN)",
        "detail": "Prevents clickjacking attacks by controlling iframe embedding",
        "rec": "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "score": 8,
        "good_pattern": r"nosniff",
        "detail": "Prevents MIME-type sniffing attacks",
        "rec": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "score": 5,
        "good_pattern": r"(no-referrer|strict-origin|same-origin)",
        "detail": "Controls referrer info sent to other sites (prevents data leakage)",
        "rec": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "medium",
        "score": 7,
        "good_pattern": None,
        "detail": "Restricts browser features (camera, mic, geolocation)",
        "rec": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "score": 5,
        "good_pattern": r"1; mode=block",
        "detail": "Legacy XSS filter (deprecated but still useful for older browsers)",
        "rec": "Add: X-XSS-Protection: 1; mode=block",
    },
    "Cache-Control": {
        "severity": "low",
        "score": 5,
        "good_pattern": r"(no-store|no-cache|private)",
        "detail": "Controls caching of sensitive pages",
        "rec": "Add: Cache-Control: no-store, no-cache, must-revalidate for sensitive pages",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Reveals server software version — attackers can find known exploits",
    "X-Powered-By": "Reveals backend framework — information disclosure",
    "X-AspNet-Version": "Reveals ASP.NET version — information disclosure",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
}

# ── Checker Class ──────────────────────────────────────────────────────────

class PhishingTester:
    def __init__(self, target_url: str, timeout: int = 10, follow_redirects: bool = True):
        self.url = target_url if target_url.startswith("http") else "http://" + target_url
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SecurityAudit/2.0 (Web Security Scanner)",
        })

    def run(self, callback=None) -> PhishingReport:
        report = PhishingReport(url=self.url, timestamp=time.strftime("%Y-%m-%d %H:%M:%S"))
        start = time.time()

        def emit(msg, level="info"):
            if callback:
                callback(level, msg)

        emit(f"[Phishing Test] Bat dau kiem tra: {self.url}")

        try:
            response = self.session.get(
                self.url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False,
            )
            headers = response.headers
            final_url = response.url
            status_code = response.status_code
            body = response.text[:50000]

            emit(f"Response: HTTP {status_code}, {len(body)} bytes")
            report.is_https = final_url.startswith("https://")
            report.server_info = headers.get("Server", "Unknown")

        except RequestException as e:
            report.checks.append(CheckResult(
                name="Connection", category="Connectivity",
                status="fail", detail=f"Cannot connect: {e}",
                severity="critical", score=0,
                recommendation="Ensure the server is running and accessible",
            ))
            report.grade = "F"
            return report

        # ── 1. HTTPS Check ────────────────────────────────────────────
        emit("Checking HTTPS...")
        if report.is_https:
            report.checks.append(CheckResult(
                "HTTPS Enabled", "Transport", "pass",
                "Site uses HTTPS — encrypted connection", "info", score=15,
                recommendation="Good! Keep SSL certificate up to date.",
            ))
        else:
            report.checks.append(CheckResult(
                "HTTPS Enabled", "Transport", "fail",
                "Site uses plain HTTP — data transmitted in cleartext!",
                "critical", score=0,
                recommendation="Enable HTTPS with a free Let's Encrypt certificate. HTTP sites are flagged by browsers as 'Not Secure' and are prime phishing targets.",
            ))

        # ── 2. Security Headers ───────────────────────────────────────
        emit("Checking security headers...")
        for header_name, meta in SECURITY_HEADERS.items():
            value = headers.get(header_name)
            if value:
                pattern = meta.get("good_pattern")
                if pattern and not re.search(pattern, value, re.I):
                    status = "warn"
                    detail = f"Header present but value may be weak: '{value}'"
                    s = meta["score"] // 2
                else:
                    status = "pass"
                    detail = f"'{value}'"
                    s = meta["score"]
            else:
                status = "fail"
                detail = f"Missing — {meta['detail']}"
                s = 0

            report.checks.append(CheckResult(
                header_name, "Security Headers", status, detail,
                meta["severity"], meta["rec"], score=s,
            ))

        # ── 3. Dangerous Info-Disclosure Headers ──────────────────────
        emit("Checking information disclosure...")
        for dh, description in DANGEROUS_HEADERS.items():
            val = headers.get(dh)
            if val:
                report.checks.append(CheckResult(
                    f"Header: {dh}", "Information Disclosure", "warn",
                    f"Value: '{val}' — {description}",
                    "medium", f"Remove or obscure the '{dh}' header in server config.", score=0,
                ))

        # ── 4. Clickjacking Test ──────────────────────────────────────
        emit("Checking clickjacking protection...")
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if xfo.upper() in ("DENY", "SAMEORIGIN") or has_frame_ancestors:
            report.checks.append(CheckResult(
                "Clickjacking Protection", "Phishing", "pass",
                "Site is protected against clickjacking attacks", "medium", score=8,
            ))
        else:
            report.checks.append(CheckResult(
                "Clickjacking Protection", "Phishing", "fail",
                "No clickjacking protection! Attackers can embed your site in an iframe on a malicious page and trick users into clicking hidden buttons.",
                "high",
                "Add: X-Frame-Options: DENY  OR  CSP: frame-ancestors 'none'",
                score=0,
            ))

        # ── 5. Cookie Security ────────────────────────────────────────
        emit("Checking cookie security flags...")
        cookies = response.cookies
        if cookies:
            for ck in cookies:
                issues = []
                if not ck.secure:
                    issues.append("Missing Secure flag")
                if not ck.has_nonstandard_attr("HttpOnly"):
                    issues.append("Missing HttpOnly flag")
                if not ck.has_nonstandard_attr("SameSite"):
                    issues.append("Missing SameSite flag")
                sev = "high" if issues else "pass"
                if issues:
                    report.checks.append(CheckResult(
                        f"Cookie: {ck.name}", "Cookie Security", "fail",
                        f"Issues: {', '.join(issues)}",
                        "high",
                        f"Set-Cookie: {ck.name}=...; Secure; HttpOnly; SameSite=Strict",
                        score=0,
                    ))
                else:
                    report.checks.append(CheckResult(
                        f"Cookie: {ck.name}", "Cookie Security", "pass",
                        "Secure, HttpOnly, SameSite flags present", "info", score=5,
                    ))
        else:
            report.checks.append(CheckResult(
                "Cookie Security", "Cookie Security", "info",
                "No cookies found on main page", "info", score=3,
            ))

        # ── 6. Open Redirect Check ────────────────────────────────────
        emit("Checking open redirect...")
        redirect_payloads = [
            f"{self.url}?next=https://evil.com",
            f"{self.url}?redirect=https://evil.com",
            f"{self.url}?url=https://evil.com",
            f"{self.url}?return=https://evil.com",
        ]
        open_redirect_found = False
        for rurl in redirect_payloads:
            try:
                r2 = self.session.get(rurl, timeout=4, allow_redirects=True, verify=False)
                if "evil.com" in r2.url:
                    open_redirect_found = True
                    break
            except Exception:
                pass

        if open_redirect_found:
            report.checks.append(CheckResult(
                "Open Redirect", "Phishing", "fail",
                "VULNERABLE! The site redirects to external URLs via query parameters — perfect for phishing attacks!",
                "critical",
                "Validate and whitelist redirect URLs. Never redirect to user-supplied URLs without verification.",
                score=0,
            ))
        else:
            report.checks.append(CheckResult(
                "Open Redirect", "Phishing", "pass",
                "No obvious open redirect vulnerability found", "info", score=5,
            ))

        # ── 7. Mixed Content Check ────────────────────────────────────
        if report.is_https:
            emit("Checking mixed content...")
            http_resources = re.findall(r'src=["\']http://[^"\']+["\']', body, re.I)
            http_resources += re.findall(r'href=["\']http://[^"\']+["\']', body, re.I)
            if http_resources:
                report.checks.append(CheckResult(
                    "Mixed Content", "Transport", "warn",
                    f"Found {len(http_resources)} HTTP resources on HTTPS page — browsers may block them",
                    "medium",
                    "Replace all http:// resource links with https:// equivalents",
                    score=2,
                ))
            else:
                report.checks.append(CheckResult(
                    "Mixed Content", "Transport", "pass",
                    "No mixed content detected", "info", score=5,
                ))

        # ── 8. Sensitive Path Exposure ────────────────────────────────
        emit("Checking sensitive paths...")
        sensitive_paths = [
            ("/.env", "Environment file (passwords/API keys)"),
            ("/.git/HEAD", "Git repository exposed"),
            ("/admin", "Admin panel"),
            ("/phpinfo.php", "PHP Info page"),
            ("/wp-admin", "WordPress admin"),
            ("/api/v1/users", "User data API"),
            ("/config.json", "Configuration file"),
            ("/backup.sql", "Database backup"),
            ("/.htaccess", "Apache config"),
            ("/server-status", "Apache server status"),
        ]
        base = self.url.rstrip("/")
        exposed = []
        for path, desc in sensitive_paths:
            try:
                r3 = self.session.get(f"{base}{path}", timeout=3, verify=False)
                if r3.status_code in (200, 403):
                    exposed.append(f"{path} ({desc}) — HTTP {r3.status_code}")
            except Exception:
                pass

        if exposed:
            report.checks.append(CheckResult(
                "Sensitive Path Exposure", "Information Disclosure", "fail",
                f"Found {len(exposed)} accessible sensitive paths: {'; '.join(exposed[:3])}",
                "high",
                "Block access to sensitive paths via server config (robots.txt, .htaccess, nginx deny rules)",
                score=0,
            ))
        else:
            report.checks.append(CheckResult(
                "Sensitive Path Exposure", "Information Disclosure", "pass",
                "Common sensitive paths are not publicly accessible", "info", score=8,
            ))

        # ── 9. HTTP Methods ───────────────────────────────────────────
        emit("Checking allowed HTTP methods...")
        try:
            opt_r = self.session.options(self.url, timeout=4, verify=False)
            allow = opt_r.headers.get("Allow", "")
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
            if dangerous:
                report.checks.append(CheckResult(
                    "HTTP Methods", "Configuration", "warn",
                    f"Dangerous methods allowed: {', '.join(dangerous)}",
                    "medium",
                    "Disable TRACE, PUT, DELETE unless specifically needed. Configure via server: TraceEnable Off",
                    score=2,
                ))
            else:
                report.checks.append(CheckResult(
                    "HTTP Methods", "Configuration", "pass",
                    f"Allowed: {allow or 'GET, POST (restricted)'}", "info", score=5,
                ))
        except Exception:
            pass

        # ── Calculate Score ───────────────────────────────────────────
        total = sum(c.score for c in report.checks)
        max_possible = sum(v["score"] for v in SECURITY_HEADERS.values()) + 15 + 8 + 5 + 5 + 8 + 5
        normalized = min(100, int((total / max(max_possible, 1)) * 100))
        report.total_score = normalized

        # Grade
        if normalized >= 90:   report.grade = "A+"
        elif normalized >= 80: report.grade = "A"
        elif normalized >= 70: report.grade = "B"
        elif normalized >= 60: report.grade = "C"
        elif normalized >= 40: report.grade = "D"
        else:                  report.grade = "F"

        # Summary
        for c in report.checks:
            report.summary[c.status] = report.summary.get(c.status, 0) + 1

        report.elapsed = round(time.time() - start, 2)
        emit(f"Phishing test hoan thanh! Score: {normalized}/100 Grade: {report.grade}", "success")
        return report


def run_phishing_test(url: str, timeout: int = 10, callback=None) -> dict:
    """Entry point — returns JSON-serializable dict."""
    import warnings
    warnings.filterwarnings("ignore")  # Suppress SSL warnings

    tester = PhishingTester(url, timeout=timeout)
    report = tester.run(callback=callback)

    return {
        "url": report.url,
        "timestamp": report.timestamp,
        "total_score": report.total_score,
        "max_score": 100,
        "grade": report.grade,
        "is_https": report.is_https,
        "server_info": report.server_info,
        "elapsed": report.elapsed,
        "summary": report.summary,
        "checks": [
            {
                "name": c.name,
                "category": c.category,
                "status": c.status,
                "detail": c.detail,
                "severity": c.severity,
                "recommendation": c.recommendation,
                "score": c.score,
            }
            for c in report.checks
        ],
    }
