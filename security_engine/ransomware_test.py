import time, threading
from dataclasses import dataclass, field
from typing import List
import requests, urllib3
urllib3.disable_warnings()

SQL_ERRORS = ["sql syntax","mysql_fetch","ORA-","You have an error in your SQL","pg_query"]
SQLI = ["QUOTE", "1 OR 1=1"]
BACKUP = ["/.env","/.git/config","/database.sql","/.htpasswd","/secrets.json","/dump.sql"]
UPLOAD_EP = ["/upload","/uploads","/api/upload","/api/files"]
AUTH_EP = ["/login","/admin","/api/login"]
DEF_CREDS = [("admin","admin"),("admin","password"),("root","root")]
SAPI = ["/api/users","/api/admin","/graphql","/swagger.json"]

@dataclass
class VulnResult:
    test_name: str
    category: str
    status: str
    detail: str
    severity: str
    payload_used: str = ""
    recommendation: str = ""
    risk_score: int = 0

@dataclass
class RansomwareReport:
    url: str
    timestamp: str = ""
    overall_risk: str = "Unknown"
    risk_score: int = 0
    results: List[VulnResult] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    elapsed: float = 0.0

class RansomwareTester:
    def __init__(self, url, timeout=8):
        self.url = url.rstrip("/") if url.startswith("http") else "http://" + url.rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "SecurityAudit/3.0"
        self._stop = threading.Event()

    def stop(self): self._stop.set()

    def _get(self, path):
        try: return self.s.get(self.url + path, timeout=self.timeout, verify=False)
        except: return None

    def _post(self, path, **kw):
        try: return self.s.post(self.url + path, timeout=self.timeout, verify=False, **kw)
        except: return None

    def run(self, callback=None):
        rep = RansomwareReport(url=self.url, timestamp=time.strftime("%Y-%m-%d %H:%M:%S"))
        start = time.time()
        em = (lambda l, m: callback(l, m)) if callback else (lambda l, m: None)
        em("info", f"[Ransomware] Scanning: {self.url}")

        self._test_backup(rep, em)
        self._test_sql(rep, em)
        self._test_creds(rep, em)
        self._test_api(rep, em)
        self._test_upload(rep, em)

        rep.elapsed = round(time.time() - start, 2)
        for v in rep.results:
            if v.status == "vulnerable":
                if v.severity == "critical": rep.critical_count += 1
                elif v.severity == "high": rep.high_count += 1
                else: rep.medium_count += 1

        raw = sum(v.risk_score for v in rep.results)
        rep.risk_score = min(100, int(raw / max(len(rep.results) * 10, 1) * 100))

        if rep.critical_count >= 2: rep.overall_risk = "Critical"
        elif rep.critical_count >= 1: rep.overall_risk = "High"
        elif rep.high_count >= 2: rep.overall_risk = "High"
        elif rep.high_count >= 1: rep.overall_risk = "Medium"
        elif rep.medium_count >= 1: rep.overall_risk = "Low"
        else: rep.overall_risk = "Safe"

        em("success", f"[Ransomware] Done. Risk: {rep.overall_risk} ({rep.risk_score}/100)")
        return rep

    def _add(self, rep, *args, **kw):
        rep.results.append(VulnResult(*args, **kw))

    def _test_backup(self, rep, em):
        em("info", "Checking backup/config exposure...")
        found = []
        for path in BACKUP:
            if self._stop.is_set(): return
            r = self._get(path)
            if r and r.status_code == 200 and len(r.content) > 20:
                cred_keys = ["password", "secret", "api_key", "token", "host=", "db_"]
                label = " CREDENTIALS EXPOSED" if any(k in r.text.lower() for k in cred_keys) else ""
                if len(r.content) > 50: found.append(f"{path}{label} ({len(r.content)}b)")
        if found:
            sev = "critical" if "CREDENTIALS" in found[0] else "high"
            self._add(rep, "Backup/Config Exposure", "Info Disclosure", "vulnerable",
                      f"{len(found)} sensitive files accessible: {found[0]}", sev, found[0],
                      "Remove backups from webroot. Deny .env .sql .git via server config.",
                      risk_score=9 if sev == "critical" else 7)
        else:
            self._add(rep, "Backup Exposure", "Info Disclosure", "safe",
                      "No exposed backup or config files found", "info",
                      recommendation="Run periodic audits on webroot contents")

    def _test_sql(self, rep, em):
        em("info", "Checking SQL injection...")
        payloads = ["'", "1 OR 1=1"]
        for ep in ["/", "/login", "/search"]:
            for pl in payloads:
                if self._stop.is_set(): return
                r = self._get(f"{ep}?id={pl}")
                if r and any(e.lower() in r.text.lower() for e in SQL_ERRORS):
                    self._add(rep, "SQL Injection", "Injection", "vulnerable",
                              f"SQL error exposed at GET {ep}", "critical", pl,
                              "Use parameterized queries. NEVER concatenate user input into SQL.",
                              risk_score=9)
                    return
                r2 = self._post(ep, data={"username": pl, "search": pl})
                if r2 and any(e.lower() in r2.text.lower() for e in SQL_ERRORS):
                    self._add(rep, "SQL Injection", "Injection", "vulnerable",
                              f"SQL error at POST {ep}", "critical", pl,
                              "Use prepared statements.", risk_score=9)
                    return
        self._add(rep, "SQL Injection", "Injection", "safe",
                  "No SQL injection found", "info",
                  recommendation="Keep using parameterized queries")

    def _test_creds(self, rep, em):
        em("info", "Checking default credentials...")
        for ep in AUTH_EP[:2]:
            r = self._get(ep)
            if not r or r.status_code not in (200, 401, 403): continue
            for user, pwd in DEF_CREDS:
                if self._stop.is_set(): return
                r2 = self._post(ep, data={"username": user, "password": pwd})
                if r2 and r2.status_code in (200, 302):
                    if any(k in r2.text.lower() for k in ["dashboard", "welcome", "logout"]):
                        self._add(rep, "Default Credentials", "Authentication", "vulnerable",
                                  f"Login with {user}:{pwd} at {ep}!", "critical",
                                  f"{user}:{pwd}",
                                  "Change all default passwords. Add lockout after 5 attempts. Enable MFA.",
                                  risk_score=10)
                        return
        self._add(rep, "Default Credentials", "Authentication", "safe",
                  "No default credentials accepted", "info",
                  recommendation="Enforce strong passwords and lockout policy")

    def _test_api(self, rep, em):
        em("info", "Checking unauthenticated API endpoints...")
        found = []
        for path in SAPI:
            if self._stop.is_set(): return
            r = self._get(path)
            if r and r.status_code == 200:
                try: r.json(); found.append(path + " open without auth")
                except: pass
        if found:
            self._add(rep, "Unauthenticated API", "Authentication", "warn",
                      f"{len(found)} API endpoints open: {found[0]}", "high",
                      recommendation="Require JWT/OAuth2 on all API endpoints.",
                      risk_score=7)
        else:
            self._add(rep, "API Endpoint Security", "Authentication", "safe",
                      "No unauthenticated sensitive API endpoints found", "info",
                      recommendation="Keep enforcing auth on all endpoints")

    def _test_upload(self, rep, em):
        em("info", "Checking file upload endpoints...")
        found = [ep for ep in UPLOAD_EP if (r := self._get(ep)) and r.status_code in (200, 405, 403)]
        if not found:
            self._add(rep, "File Upload", "File Upload", "info",
                      "No obvious upload endpoints found", "low",
                      recommendation="Ensure uploads require auth and validate file types")
            return
        vuln = []
        for ep in found[:2]:
            php_shell = b"<?php system(chr(105)); ?>"
            r = self._post(ep, files={"file": ("shell.php", php_shell, "application/x-php")})
            if r and r.status_code in (200, 201):
                vuln.append(f"{ep} accepted shell.php")
                em("error", f"CRITICAL: PHP shell uploaded to {ep}!")
        if vuln:
            self._add(rep, "File Upload Vulnerability", "File Upload", "vulnerable",
                      f"Server accepted malicious files: {vuln[0]}", "critical", "shell.php",
                      "Whitelist allowed extensions. Scan uploads. Store outside webroot.",
                      risk_score=10)
        else:
            self._add(rep, "File Upload Security", "File Upload", "safe",
                      f"Checked {len(found)} endpoints, no unrestricted upload found", "info",
                      recommendation="Keep enforcing file type validation")


def run_ransomware_test(url: str, timeout: int = 8, callback=None) -> dict:
    import warnings; warnings.filterwarnings("ignore")
    tester = RansomwareTester(url, timeout=timeout)
    rep = tester.run(callback=callback)
    return {
        "url": rep.url, "timestamp": rep.timestamp,
        "overall_risk": rep.overall_risk, "risk_score": rep.risk_score,
        "critical_count": rep.critical_count, "high_count": rep.high_count,
        "medium_count": rep.medium_count, "elapsed": rep.elapsed,
        "results": [{"test_name": v.test_name, "category": v.category, "status": v.status,
                     "detail": v.detail, "severity": v.severity, "payload_used": v.payload_used[:80],
                     "recommendation": v.recommendation, "risk_score": v.risk_score}
                    for v in rep.results],
    }