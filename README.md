# 🛡️ VulnScanner

A web-based network vulnerability scanner built on **Nmap**, with a clean dark UI and one-click **PDF report generation**.

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## Features

- **10 Nmap scan profiles** — Quick, Standard, Full, Vuln, UDP, Stealth, OS Detection, Aggressive, Ping Sweep, Firewall Evasion
- **Live streaming output** — real-time log feed during scan
- **Auto risk classification** — ports and services scored Critical / High / Medium / Low
- **NSE vulnerability scripts** — detects known CVEs via Nmap's vuln scripts
- **PDF report** — downloadable report with port table, findings, and recommendations
- **Docker-ready** — single `docker-compose up` deployment

---

## Scan Profiles

| Profile | Nmap Args | Description |
|---|---|---|
| Quick | `-T4 -F --open` | Top 100 ports, fast |
| Standard | `-sV -sC -T4 -p 1-1000` | Version + scripts, top 1000 ports |
| Full Port | `-sV -sC -T4 -p-` | All 65535 ports |
| Vulnerability | `-sV -sC --script=vuln -T4` | NSE vuln scripts |
| UDP | `-sU -sV -T4 --top-ports 200` | Top 200 UDP ports |
| Stealth SYN | `-sS -sV -T3 -p 1-1000` | Requires root/sudo |
| OS Detection | `-O -sV -T4` | Requires root/sudo |
| Aggressive | `-A -T4` | OS + version + scripts + traceroute |
| Ping Sweep | `-sn` | Host discovery only |
| Firewall Evasion | `-sA -T4 -p 1-1000` | ACK scan for firewall mapping |

---

## Quick Start (Docker — Recommended)

```bash
git clone https://github.com/YOUR_USERNAME/vuln-scanner.git
cd vuln-scanner
docker-compose up --build
```

Open **http://localhost:5000**

> **Note:** OS detection (`-O`) and SYN stealth scan (`-sS`) require `NET_RAW`/`NET_ADMIN` capabilities. The provided `docker-compose.yml` includes them.

---

## Local Development

**Prerequisites:** Node.js 18+, Nmap installed

```bash
# Install all dependencies
npm run install:all

# Run dev (server + client with hot reload)
npm run dev
```

- Server: http://localhost:5000
- Client (dev): http://localhost:3000

**Install Nmap:**
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Windows: https://nmap.org/download.html
```

---

## Production Build

```bash
npm run build    # builds React client
npm start        # serves everything from port 5000
```

---

## Deploy to a VPS / Cloud Server

```bash
# On your server (Ubuntu example)
git clone https://github.com/YOUR_USERNAME/vuln-scanner.git
cd vuln-scanner
docker-compose up -d

# View logs
docker-compose logs -f
```

For HTTPS, put Nginx or Caddy in front:

```nginx
server {
    listen 443 ssl;
    server_name scanner.yourdomain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
    }
}
```

---

## GitHub Actions (CI/CD)

Add these secrets to your GitHub repo (`Settings → Secrets`):

- `DOCKERHUB_USERNAME` — your Docker Hub username
- `DOCKERHUB_TOKEN` — your Docker Hub access token

On every push to `main`, the image is built and pushed to Docker Hub automatically.

---

## Project Structure

```
vuln-scanner/
├── server/
│   └── index.js          # Express API + Nmap exec + PDF generation
├── client/
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── App.js         # Full React UI
│       ├── index.js
│       └── index.css
├── reports/               # Generated PDFs (git-ignored)
├── Dockerfile
├── docker-compose.yml
├── package.json
└── .github/
    └── workflows/
        └── docker.yml
```

---

## PDF Report Contents

- Scan metadata (target, profile, timestamp)
- Stats summary (hosts, open ports, findings, criticals)
- Per-host: open port table with risk levels
- Per-host: security findings with details
- General remediation recommendations

---

## Legal

This tool is provided for **authorized security testing, education, and research only**.  
The authors are not responsible for misuse. Always obtain written permission before scanning.
