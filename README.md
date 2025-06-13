# Deep-Recon

Deep-Recon is a professional, modular toolkit for web reconnaissance and vulnerability analysis. It is built for penetration testers, security researchers, and red teamers who require comprehensive and actionable intelligence on modern web environments. With its blend of advanced detection logic, automation, and professional reporting, Deep-Recon delivers both speed and depth for your security assessments.

---

## 🚩 Key Features

### Reconnaissance & Fingerprinting
- **Comprehensive CMS Detection:**  
  Uncovers WordPress, Drupal, Joomla, Magento, and other platforms. Enumerates plugins, themes, users, configuration, and backup files. Detects outdated versions and exposed sensitive files for deeper risk analysis.

- **Technology Stack Detection:**  
  Goes beyond CMS — fingerprints backend frameworks (Laravel, Django, Express, Spring, ASP.NET), server software (Apache, Nginx, PHP), and modern frontend stacks (React, Angular, Vue, jQuery, Bootstrap) using headers, cookies, meta tags, and content inspection.

- **WAF Detection and Bypass:**  
  Identifies common Web Application Firewalls and automatically generates custom headers for bypass attempts, improving scan coverage and reliability.

### Vulnerability Analysis
- **Automated Vulnerability Scanning:**  
  Checks for XSS, SQL Injection, LFI, SSRF, Open Redirect, and more. Uses up-to-date payloads and evaluates both risk and exploitability for accurate prioritization.

- **Security Header Analysis:**  
  Audits key HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more). Flags weak or missing headers and provides actionable remediation advice.

- **Outdated Software & Exposed Config Detection:**  
  Detects known vulnerable versions of software and CMS, and identifies exposed configuration or debug files that could leak sensitive data.

### Threat Intelligence
- **CVE Lookup & Vulnerability Intelligence:**  
  Integrates CVE database lookups for discovered technologies, complete with scoring, exploitability checks, and caching to accelerate results during larger engagements.

### Infrastructure Recon
- **DNS Enumeration:**  
  Queries and enumerates A, NS, MX, and TXT records for domains. Supports caching and stealth options for efficient and low-profile recon.

- **WHOIS Lookup:**  
  Supports robust single, asynchronous, and bulk WHOIS queries with caching and proxy support, making it practical for both focused and large-scope assessments.

### Reporting & Export
- **Professional Report Generation:**  
  Creates clear, client-ready HTML reports with interactive and collapsible sections for findings, AI-powered analysis, and full raw data. Export findings to JSON for further processing or integration with other tools.

- **AI-Powered Analysis:**  
  Leverages AI for structured, prioritized, and actionable security recommendations, including risk assessment and remediation advice.

### Performance, Evasion, and Usability
- **Smart Caching:**  
  Uses SQLite and in-memory caching for fast lookups of CVE, DNS, and WHOIS data. Reduces redundant requests and speeds up repeated scans.

- **Stealth Mode:**  
  Features proxy support, random delays, and user-agent rotation to minimize detection and evade rate limits during active engagements.

- **Batch Operations:**  
  Handles bulk DNS, WHOIS, and recon scans to efficiently process large asset lists or entire organizations.

- **Interactive Reports:**  
  HTML reports are enhanced with collapsible sections, keyboard shortcuts, and smooth scrolling for maximum clarity and usability.

---

## 📂 Project Structure

| File/Folder               | Purpose                                                           |
|---------------------------|-------------------------------------------------------------------|
| `cms.py`                  | CMS detection, plugin/theme/user/config enumeration               |
| `dir_enum.py`             | Directory and technology stack scanning, WAF detection            |
| `header_analyzer.py`      | HTTP header & security header auditing                            |
| `http_fingerprint.py`     | Web server & technology fingerprinting                            |
| `vuln_scan.py`            | Web vulnerability scanning (XSS, SQLi, LFI, SSRF, etc.)           |
| `cve_lookup.py`           | CVE and threat intelligence integration, smart caching            |
| `dns_enum.py`             | DNS record enumeration with caching                               |
| `report_generator.py`     | Automated report (HTML/JSON) generation and AI analysis           |
| `report.html`,<br>`basic_report_template.html`,<br>`enhanced_html_template.html` | Reporting templates for findings and analysis       |

---

## ⚙️ Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/zain1234-lab/Deep-Recon.git
   cd Deep-Recon
   ```

2. **Install Dependencies**  
   Requires Python 3.8+  
   ```bash
   pip install -r requirements.txt
   ```
   If you’re missing the requirements file, ensure you have: `requests`, `jinja2`, `pyyaml`, `aiohttp`, `packaging`, `dnspython`.

---

## 🚦 Usage

Deep-Recon is modular and can be used for single tasks or integrated into your workflow.

**CMS Detection**
```bash
python cms.py --url https://targetsite.com
```

**Vulnerability Scan**
```bash
python vuln_scan.py --url https://targetsite.com
```

**DNS Enumeration**
```bash
python dns_enum.py --domain targetsite.com
```

**Batch WHOIS Lookup**
```bash
python whois_batch.py --input domains.txt
```

**Generate a Report**
```bash
python report_generator.py --input findings.json --output report.html
```

For more options, run any script with `-h` or `--help`.

---

## 🧠 How It Works

- Combines heuristic and signature-based detection for reliable technology and vulnerability identification.
- Enumerates and probes endpoints for plugins, themes, users, configs, and backups.
- Checks for modern attacks and misconfigurations.
- Looks up threat intelligence and CVEs for context.
- Collates findings into professional reports, with actionable remediation guidance.

---

## 🛡️ Legal & Ethical Notice

> Deep-Recon is intended **only** for authorized security testing.  
> Do not scan targets without explicit permission.  
> The author bears no responsibility for misuse or illegal activity.

---

## 🤝 Contributing

Found a bug or want to propose a feature?  
Open an issue or pull request at [GitHub](https://github.com/zain1234-lab/Deep-Recon).

---

## 📖 License

Licensed under the MIT License. See [LICENSE](LICENSE).

---

## ✉️ Contact

For questions or support, open an issue or reach out via GitHub.

---

*Deep-Recon: Security through clarity, precision, and automation.*
