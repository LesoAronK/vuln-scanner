# ⬡ VulnScan — Web Vulnerability Scanner

A simple, browser-based **passive vulnerability scanner** that checks web applications for common security misconfigurations. Built as an educational mini-project for learning penetration testing concepts.

🔗 **Live Demo:

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
---

## Project Structure

```
vulnscan/
├── index.html         
├── css/
│   └── style.css       
├── js/
│   └── scanner.js      
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
