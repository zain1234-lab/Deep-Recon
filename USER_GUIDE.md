# Deep-Recon User Guide

Deep-Recon is a modular, extensible reconnaissance automation tool for penetration testers, bug bounty hunters, and security researchers. It automates a wide range of recon tasks against a given target (domain or IP), provides flexible module selection, supports proxy usage, database/storage integration, and generates advanced reports.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Command-Line Arguments](#command-line-arguments)
4. [Modules](#modules)
5. [Usage Examples](#usage-examples)
6. [Output & Reports](#output--reports)
7. [Proxy Support](#proxy-support)
8. [Database Integration](#database-integration)
9. [Stealth Mode](#stealth-mode)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/zain1234-lab/Deep-Recon.git
   cd Deep-Recon
   ```

2. **Install dependencies:**
   - It's recommended to use a Python 3.8+ virtual environment.
   - Install requirements:
     ```bash
     pip install -r requirements.txt
     ```

3. **(Optional) Prepare Proxy List:**
   - If you want to use proxies, create or update `proxy_list.txt` in the repo directory.

---

## Quick Start

```bash
python main.py --target example.com
```
- This will run all enabled modules against the target `example.com` and output results to the `recon_results` directory.

---

## Command-Line Arguments

| Argument                   | Description                                                                                                      | Example                                  |
|----------------------------|------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| `--target`, `-t`           | **(Required)** Target IP or domain.                                                                              | `--target example.com`                   |
| `--ports`                  | Comma-separated list of ports (defaults: 80,443).                                                                | `--ports 80,8080,443`                    |
| `--modules`                | List of modules to run, or `all` for all modules.                                                                | `--modules port_scan banner_grab`        |
| `--stealth`                | Enable random delays for stealth scanning.                                                                       | `--stealth`                              |
| `--db`                     | SQLite database path for storing results.                                                                        | `--db myscan.db`                         |
| `--output`                 | Output directory for reports and results.                                                                        | `--output results_dir`                   |
| `--verbose`                | Enable verbose logging (debug mode).                                                                             | `--verbose`                              |
| `--use-proxy`              | Enable proxy usage for outbound connections.                                                                     | `--use-proxy`                            |
| `--proxy-list`             | Path to proxy list file.                                                                                         | `--proxy-list myproxies.txt`             |
| `--deepseek-api-key`       | API key for DeepSeek AI analysis (if required by cve_lookup/report modules).                                     | `--deepseek-api-key XXX`                 |
| `--concurrency-limit`      | Maximum concurrent requests/workers (default: 10).                                                               | `--concurrency-limit 5`                  |
| `--report-base-name`       | Custom base name for generated report files (default: derived from target).                                      | `--report-base-name myscan`              |

---

## Modules

- You can run any combination of modules via `--modules`, or use `all` to run every available module.

| Module Name         | Description                                 |
|---------------------|---------------------------------------------|
| `port_scan`         | TCP port scanning                           |
| `banner_grab`       | Service banner grabbing                     |
| `cms`               | CMS reconnaissance                          |
| `http_fingerprint`  | HTTP service fingerprinting                 |
| `dir_enum`          | Directory and file enumeration              |
| `vuln_scan`         | Basic vulnerability scanning                |
| `dns_enum`          | DNS enumeration                             |
| `subdomains`        | Subdomain enumeration                       |
| `whois_lookup`      | WHOIS and registry info                     |
| `firewall_detect`   | Firewall/WAF detection                      |
| `header_analyzer`   | HTTP header analysis                        |
| `cve_lookup`        | CVE matching & vulnerability lookup         |
| `db_integration`    | Store results in SQLite database            |
| `report_generator`  | Generate comprehensive/advanced reports     |

---

## Usage Examples

**Full scan with all modules (domain):**
```bash
python main.py --target example.com --modules all
```

**Port scan and CMS recon only (IP):**
```bash
python main.py --target 192.168.1.10 --modules port_scan cms
```

**Stealth scan with proxies and verbose output:**
```bash
python main.py -t testsite.com --stealth --use-proxy --verbose
```

**Custom output directory, report base name, and limited concurrency:**
```bash
python main.py -t mysite.com --output outdir --report-base-name test1 --concurrency-limit 3
```

---

## Output & Reports

- By default, results are saved in the `recon_results` directory (customizable via `--output`).
- At the end, you will be prompted interactively to select which types of reports to generate (e.g., advanced, comprehensive).
- The tool outputs findings in JSON, HTML, and/or other formats, with file paths shown on completion.

---

## Proxy Support

- Enable proxy usage with `--use-proxy`.
- Place proxies (one per line) in the file specified by `--proxy-list` (default: `proxy_list.txt`).
- The tool will attempt to use healthy proxies for relevant modules.

---

## Database Integration

- Specify a database file using `--db myscan.db`.
- Results are stored for future querying or analysis.
- If the database or required modules are unavailable, the tool will continue and log a warning.

---

## Stealth Mode

- Enable stealth mode with `--stealth`.
- Random delays are inserted between requests to minimize detection.

---

## Troubleshooting

- If a module is missing or a dependency cannot be imported, a warning will be shown and the scan will continue with available modules.
- Enable `--verbose` for detailed debugging output.
- Ensure all required Python packages are installed (see `requirements.txt`).

---

## FAQ

**Q: How can I run only subdomain and DNS enumeration?**  
A:  
```bash
python main.py --target example.com --modules subdomains dns_enum
```

**Q: How do I add more modules?**  
A:  
Place your module script in the project directory. Follow the import structure in `main.py` and add its functions to the `modules` dictionary.

**Q: What if a module fails?**  
A:  
Failures are logged, and the tool continues with other modules.

**Q: How do I use proxies?**  
A:  
Enable with `--use-proxy` and provide a non-empty `proxy_list.txt`.

**Q: How do I get advanced or comprehensive reports?**  
A:  
When prompted near the end of the scan, select the report numbers as shown (e.g., `1,2` for both advanced and comprehensive).

---

## Support

- For issues, open an [issue on GitHub](https://github.com/zain1234-lab/Deep-Recon/issues).
- For further help, read module docstrings or use `--verbose` for more information.

---

**Happy Recon!**