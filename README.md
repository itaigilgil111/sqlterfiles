# SQLi-Recon


  ___  ___  _    _   ___
 / __|/ _ \\| |  (_) / __| __ __ _ _ _  _ _  ___ _ _. _ _
 \\__ \\ (_) | |_ | | \\__ \\/ _/ _` | ' \\| ' \\/ -_) _'_|
 |___/\\__\\___|_|_| |___/\\__\\__,_|_||_|_||_\\___|_|

**SQL Injection Vulnerability Scanner for Bug Bounty Hunters**

A detection-focused SQL injection scanner that identifies potential injection points and generates proof-of-concept evidence for responsible disclosure. Designed for authorized penetration testing and bug bounty programs.

## Features

- **Error-Based Detection** — Triggers database error messages and fingerprints the DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **Boolean-Based Blind Detection** — Compares TRUE/FALSE responses to identify injectable parameters
- **Time-Based Blind Detection** — Measures response delays to detect injection without visible output
- **DBMS Fingerprinting** — Automatically identifies the backend database from error signatures
- **Confidence Scoring** — Rates each finding from 0-100% to help prioritize real vulnerabilities
- **HackerOne Report Generator** — Outputs findings in a markdown format ready for bug bounty submissions
- **JSON Reports** — Machine-readable output for integration with other tools
- **Rich Terminal UI** — Clean, colorful output with progress bars and formatted tables
- **Proxy Support** — Route traffic through Burp Suite or other intercepting proxies
- **Custom Headers & Cookies** — Full control over request parameters for authenticated testing

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sqli-recon.git
cd sqli-recon

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Basic scan
python sqli_recon.py -u "https://example.com/page?id=1"

# Verbose scan with JSON report
python sqli_recon.py -u "https://example.com/page?id=1" -v --report findings.json

# POST request scan
python sqli_recon.py -u "https://example.com/login" -m POST -d "username=admin&password=test"

# Scan with authentication
python sqli_recon.py -u "https://example.com/api?id=1" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -c "session=abc123"

# Generate HackerOne report
python sqli_recon.py -u "https://example.com/page?id=1" --hackerone --report findings.json

# Route through Burp Suite
python sqli_recon.py -u "https://example.com/page?id=1" --proxy http://127.0.0.1:8080
```

## Usage

```
usage: sqli-recon [-u URL] [options]

Required:
  -u, --url URL         Target URL with parameters

Options:
  -m, --method          HTTP method: GET or POST (default: GET)
  -d, --data            POST data (e.g., 'user=admin&pass=test')
  -H, --header          Custom header (repeatable)
  -c, --cookie          Cookies (e.g., 'session=abc123; token=xyz')
  --timeout SECONDS     Request timeout (default: 10)
  --delay SECONDS       Delay for time-blind tests (default: 5)
  --threads N           Thread count (default: 5)
  --proxy URL           Proxy (e.g., http://127.0.0.1:8080)
  -v, --verbose         Verbose output
  --report FILE         Save JSON report
  --hackerone           Generate HackerOne markdown report
  --version             Show version
```

## How It Works

### Detection Methods

| Method | How It Works | Best For |
|--------|-------------|----------|
| Error-Based | Injects payloads that trigger database errors, then fingerprints the DBMS from error messages | Quick identification, DBMS detection |
| Boolean-Blind | Sends TRUE/FALSE conditions and compares response differences | When errors are suppressed |
| Time-Blind | Injects sleep/delay commands and measures response time | When no visible output changes |

### Confidence Scoring

Each finding is rated 0-100%:
- **90-100%**: Very high confidence — confirmed DB error with DBMS fingerprint
- **75-89%**: High confidence — strong behavioral evidence
- **50-74%**: Medium confidence — suggestive but needs manual verification
- **Below 50%**: Low confidence — possible false positive

## Example Output

```
┌─────────────────────── Findings ───────────────────────┐
│ #  │ Severity │ Type              │ Param │ DBMS  │ %  │
│ 1  │ HIGH     │ Error-Based       │ id    │ MySQL │ 90 │
│ 2  │ MEDIUM   │ Boolean-Blind     │ search│ MySQL │ 75 │
└────────────────────────────────────────────────────────┘
```

## Integrations

### Burp Suite
Route traffic through Burp for detailed request/response analysis:
```bash
python sqli_recon.py -u "https://target.com/page?id=1" --proxy http://127.0.0.1:8080
```

### Pipeline Usage
Use the exit code for CI/CD integration:
- Exit 0 = No findings
- Exit 1 = Findings detected

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.**

Only use SQLi-Recon against systems where you have **explicit written permission** to perform security testing. Unauthorized access to computer systems is illegal in most jurisdictions.

The author is not responsible for any misuse of this tool. Users must comply with all applicable laws and the rules of any bug bounty programs they participate in.

## Contributing

Pull requests welcome! Areas for contribution:
- Additional payload sets
- New detection techniques
- WAF bypass strategies
- Output format options
- Documentation improvements

## License

MIT License — see [LICENSE](LICENSE) for details.
