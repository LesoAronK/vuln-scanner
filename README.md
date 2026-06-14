# ⬡ VulnScan — Web Vulnerability Scanner

A simple, browser-based **passive vulnerability scanner** that checks web applications for common security misconfigurations. Built as an educational mini-project for learning penetration testing concepts.

🔗 **Live Demo:** `https://your-username.github.io/vulnscan`

---

## Features

| Check | What it detects |
|---|---|
| 🛡 Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 🔌 Port Exposure | FTP, SSH, Telnet, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB |
| 📦 Software Versions | Apache, Nginx, PHP, WordPress, Joomla, ASP.NET version disclosures |
| 🔒 SSL / TLS | HTTPS enforcement, weak ciphers, deprecated TLS versions, expiring certs |

- Findings sorted by severity: **HIGH → MEDIUM → LOW → INFO**
- Downloadable `.txt` vulnerability report
- Entirely client-side — no backend, no data sent

---

## Deploy to GitHub Pages

### Option 1 — Upload via GitHub UI

1. Create a new GitHub repository (e.g. `vulnscan`)
2. Upload all files keeping the folder structure:
   ```
   index.html
   css/style.css
   js/scanner.js
   README.md
   ```
3. Go to **Settings → Pages → Source → Deploy from branch → main → / (root)**
4. Your site will be live at `https://your-username.github.io/vulnscan`

### Option 2 — Git CLI

```bash
git clone https://github.com/your-username/vulnscan.git
cd vulnscan
# copy these files in
git add .
git commit -m "Initial VulnScan release"
git push origin main
# Enable Pages in repo settings
```

---

## Project Structure

```
vulnscan/
├── index.html          # Main page & UI
├── css/
│   └── style.css       # All styles (dark terminal theme)
├── js/
│   └── scanner.js      # Scan logic, checks database, report generator
└── README.md
```

---

## ⚠️ Disclaimer

This tool performs **passive, simulated checks only**. No actual network packets are sent to target hosts from the browser. This project is for **educational purposes** to understand:

- Common web security headers and their purpose
- Which network ports represent attack surface
- How software version disclosure aids attackers
- How to structure a vulnerability report

**Only test systems you own or have explicit permission to assess.**

---

## Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [SSL Labs Test](https://www.ssllabs.com/ssltest/)
- [Security Headers](https://securityheaders.com/)
