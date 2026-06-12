# 🛡️ VulnScanner

A browser-based network vulnerability scanner — runs entirely on GitHub Pages, no server needed.

**Live demo:** `https://YOUR_USERNAME.github.io/vuln-scanner`

---

## Deploy in 2 steps

**1. Create the repo**

```
New repo on GitHub → name it vuln-scanner → upload index.html
```

**2. Enable GitHub Pages**

```
Repo → Settings → Pages → Source: Deploy from branch → Branch: main → / (root) → Save
```

Done. Your scanner is live at `https://YOUR_USERNAME.github.io/vuln-scanner`

---

## How to use it

1. Get an Anthropic API key from [console.anthropic.com](https://console.anthropic.com)
2. Open the scanner, paste your key — it stays in your browser session only
3. Enter a target (IP, hostname, or CIDR range)
4. Pick a scan profile, hit Start

The report appears inline — no downloads, no installs.

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

## Privacy

- Your API key is stored in `sessionStorage` only — cleared when you close the tab
- Scan requests go directly from your browser to `api.anthropic.com`
- No data is stored or logged anywhere

---

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit written permission to test.
