# 🛡️ VulnScanner

A browser-based network vulnerability scanner — runs entirely on GitHub Pages, no server needed.


## How to use it

1. Get an Anthropic API key from [console.anthropic.com](https://console.anthropic.com)
2. Open the scanner, paste your key — it stays in your browser session only
3. Enter a target (IP, hostname, or CIDR range)
4. Pick a scan profile, hit Start

The report appears online — no downloads, no installs.

---

## Scan profiles

| Profile | Nmap equivalent | Use for |
|---|---|---|
| Quick | `-T4 -F --open` | Fast first look |
| Standard | `-sV -sC -T4 -p 1-1000` | General assessment |
| Full | `-sV -sC -T4 -p-` | Thorough audit |
| Vulnerability | `--script=vuln` | CVE detection |
| UDP | `-sU --top-ports 200` | UDP services |
| Stealth SYN | `-sS -T3` | Evasive scan |
| OS Detection | `-O -sV` | Fingerprinting |
| Aggressive | `-A -T4` | Everything |
| Ping Sweep | `-sn` | Host discovery |
| Firewall Evasion | `-sA` | Firewall mapping |

---
