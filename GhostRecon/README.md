# Black-Box Reconnaissance Toolkit

A comprehensive Phase 1 reconnaissance automation framework for authorized penetration testing engagements. This toolkit performs passive and active reconnaissance to map attack surfaces, discover subdomains, fingerprint technologies, and hunt for exposed sensitive files.

> **⚠️ DISCLAIMER:** This tool is intended for authorized security testing only. Always obtain proper written authorization before testing any target. The author assumes no liability for misuse.

## Features

- **DNS Enumeration** — A, MX, NS, TXT record resolution
- **Subdomain Bruteforce** — Customizable wordlist-based discovery
- **Technology Fingerprinting** — Framework, server, and WAF detection
- **Sensitive File Hunt** — `.env`, config files, backups, git exposure
- **SSL/TLS Analysis** — Certificate inspection and cipher detection
- **Port Scanning** — Lightweight multi-threaded port scanning
- **WAF Evasion** — Rotating User-Agents, request delays, encoding tricks
- **Modular Design** — Use individual modules or run full reconnaissance

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/BlackBox-Recon-Toolkit.git
cd BlackBox-Recon-Toolkit
pip install -r requirements.txt
```

## Quick Start

```bash
# Full reconnaissance
python src/recon_toolkit.py -d example.com

# With custom options
python src/recon_toolkit.py -d example.com -t 20 --timeout 20 --delay-min 1.0 --delay-max 3.0
```

## Usage

```
usage: recon_toolkit.py [-h] -d DOMAIN [-u URL] [-t THREADS] [--timeout TIMEOUT]
                        [--delay-min DELAY_MIN] [--delay-max DELAY_MAX]

Black-Box Reconnaissance Toolkit

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain (e.g., example.com)
  -u URL, --url URL     Target URL (default: https://domain)
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  --timeout TIMEOUT     Request timeout (default: 15)
  --delay-min DELAY_MIN
                        Minimum delay between requests
  --delay-max DELAY_MAX
                        Maximum delay between requests
```

## Methodology

### Phase 1: Reconnaissance & OSINT

1. **Passive Reconnaissance**
   - DNS record enumeration
   - Certificate transparency logs
   - Search engine dorking
   - OSINT platform queries

2. **Active Reconnaissance**
   - Subdomain bruteforce
   - Port scanning
   - Technology fingerprinting
   - Sensitive file discovery
   - API endpoint enumeration

3. **Evasion Techniques**
   - Request throttling (configurable delays)
   - User-Agent rotation
   - Direct IP access with Host header spoofing
   - URL encoding bypasses
   - Header-based WAF bypasses

## Output Structure

```
recon_output/
├── dns_records.json
├── subdomains.json
├── technology_fingerprint.json
├── sensitive_files.json
├── ssl_analysis.json
└── port_scan.json
```

## Wordlists

The toolkit includes a curated subdomain wordlist in `wordlists/subdomains.txt`. You can replace or extend this with your own wordlists (e.g., from [SecLists](https://github.com/danielmiessler/SecLists)).

## Extending the Toolkit

The modular class-based design makes it easy to add new reconnaissance modules:

```python
from src.recon_toolkit import ReconToolkit

toolkit = ReconToolkit(target_domain="example.com")
toolkit.dns_resolution()
toolkit.subdomain_enum()
# Add your custom module here
toolkit.run_all()
```

## Security & Ethics

- **Only test targets you own or have explicit written authorization to test**
- Respect rate limits and testing windows defined in your authorization
- Do not commit recon output files or authorization documents to version control
- Report findings responsibly through proper channels

## License

[MIT License](LICENSE)

## Author

**Ukasha Mehmood** — Cybersecurity Specialist

---

*Built for authorized penetration testing engagements. Use responsibly.*
