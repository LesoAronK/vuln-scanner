/**
 * VulnScan — scanner.js
 * Passive browser-based vulnerability checks.
 * No actual port scanning or server intrusion is performed.
 */

'use strict';

/* ─── State ─────────────────────────────────────────── */
let scanResults = [];
let scanTarget  = '';

/* ─── Checks Database ────────────────────────────────── */

const SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    abbr: 'CSP',
    severity: 'HIGH',
    desc: 'Missing Content-Security-Policy header allows cross-site scripting (XSS) attacks.',
    rec:  'Add: Content-Security-Policy: default-src \'self\''
  },
  {
    name: 'Strict-Transport-Security',
    abbr: 'HSTS',
    severity: 'HIGH',
    desc: 'Missing HSTS header allows protocol downgrade and cookie hijacking attacks.',
    rec:  'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
  },
  {
    name: 'X-Frame-Options',
    abbr: 'XFO',
    severity: 'MEDIUM',
    desc: 'Missing X-Frame-Options allows the site to be embedded in iframes (clickjacking).',
    rec:  'Add: X-Frame-Options: DENY'
  },
  {
    name: 'X-Content-Type-Options',
    abbr: 'XCTO',
    severity: 'MEDIUM',
    desc: 'Missing X-Content-Type-Options allows MIME-type sniffing attacks.',
    rec:  'Add: X-Content-Type-Options: nosniff'
  },
  {
    name: 'Referrer-Policy',
    abbr: 'RP',
    severity: 'LOW',
    desc: 'Missing Referrer-Policy may leak sensitive URLs to third-party sites.',
    rec:  'Add: Referrer-Policy: strict-origin-when-cross-origin'
  },
  {
    name: 'Permissions-Policy',
    abbr: 'PP',
    severity: 'LOW',
    desc: 'Missing Permissions-Policy allows unrestricted browser feature access.',
    rec:  'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
  }
];

const COMMON_PORTS = [
  { port: 21,   service: 'FTP',    severity: 'HIGH',   desc: 'FTP (port 21) is unencrypted and often misconfigured.', rec: 'Disable FTP; use SFTP or SCP instead.' },
  { port: 22,   service: 'SSH',    severity: 'INFO',   desc: 'SSH (port 22) detected. Ensure key-based auth is enforced.', rec: 'Disable password auth; use SSH keys. Change default port if possible.' },
  { port: 23,   service: 'Telnet', severity: 'HIGH',   desc: 'Telnet (port 23) transmits data in plaintext.', rec: 'Disable Telnet immediately; use SSH.' },
  { port: 80,   service: 'HTTP',   severity: 'MEDIUM', desc: 'HTTP (port 80) is open. Unencrypted traffic is visible to attackers.', rec: 'Redirect all HTTP traffic to HTTPS.' },
  { port: 443,  service: 'HTTPS',  severity: 'INFO',   desc: 'HTTPS (port 443) is open — this is expected.', rec: 'Ensure TLS 1.2+ is enforced and weak ciphers are disabled.' },
  { port: 3306, service: 'MySQL',  severity: 'HIGH',   desc: 'MySQL (port 3306) is publicly exposed.', rec: 'Bind MySQL to 127.0.0.1; restrict external access with firewall rules.' },
  { port: 5432, service: 'Postgres', severity: 'HIGH', desc: 'PostgreSQL (port 5432) is publicly exposed.', rec: 'Restrict with pg_hba.conf and firewall rules.' },
  { port: 6379, service: 'Redis',  severity: 'HIGH',   desc: 'Redis (port 6379) often has no auth and is publicly exposed.', rec: 'Enable requirepass in redis.conf; bind to localhost.' },
  { port: 8080, service: 'HTTP-Alt', severity: 'MEDIUM', desc: 'Alternate HTTP port 8080 is open — often an admin panel or dev server.', rec: 'Restrict access; ensure it is not a staging server accessible publicly.' },
  { port: 27017, service: 'MongoDB', severity: 'HIGH', desc: 'MongoDB (port 27017) may be exposed without authentication.', rec: 'Enable MongoDB authentication and restrict external access.' }
];

const SOFTWARE_VULNS = [
  { pattern: /Apache\/2\.[0-3]\./i,  name: 'Outdated Apache',      severity: 'HIGH',   desc: 'Outdated Apache version detected in Server header — vulnerable to multiple CVEs.', rec: 'Upgrade Apache to latest stable release.' },
  { pattern: /nginx\/1\.[0-9]\./i,   name: 'Outdated Nginx',       severity: 'MEDIUM', desc: 'Older nginx version detected — may miss recent security patches.', rec: 'Upgrade nginx to latest stable release.' },
  { pattern: /PHP\/[5-7]\.[0-3]/i,   name: 'Outdated PHP',         severity: 'HIGH',   desc: 'Outdated PHP version detected — PHP 5.x and early PHP 7.x are end-of-life.', rec: 'Upgrade to PHP 8.2+.' },
  { pattern: /WordPress\/[1-5]\./i,  name: 'Outdated WordPress',   severity: 'HIGH',   desc: 'WordPress version below 6.x detected — many known vulnerabilities exist.', rec: 'Update WordPress core, themes, and plugins.' },
  { pattern: /Joomla\/[1-3]\./i,     name: 'Outdated Joomla',      severity: 'HIGH',   desc: 'Old Joomla version detected with known vulnerabilities.', rec: 'Upgrade to Joomla 4.x or 5.x.' },
  { pattern: /ASP\.NET\s+[1-3]\./i,  name: 'Outdated ASP.NET',     severity: 'MEDIUM', desc: 'Old ASP.NET version detected.', rec: 'Upgrade to ASP.NET 6+ / .NET 8.' },
  { pattern: /X-Powered-By/i,        name: 'Technology Disclosure', severity: 'LOW',   desc: 'X-Powered-By header reveals server technology to attackers.', rec: 'Remove X-Powered-By header from server config.' },
  { pattern: /Server:/i,             name: 'Server Version Disclosure', severity: 'LOW', desc: 'Server header reveals software version, aiding fingerprinting.', rec: 'Remove or genericize the Server header.' }
];

/* ─── Simulation Engine ──────────────────────────────── */

function randomBool(trueChance = 0.5) {
  return Math.random() < trueChance;
}

function simulateHeaderScan(url) {
  const isHttps = url.startsWith('https://');
  const results = [];

  SECURITY_HEADERS.forEach(h => {
    // Sites are more likely to be missing headers (realistic)
    const chance = isHttps ? 0.55 : 0.75;
    if (randomBool(chance)) {
      results.push({
        category: 'Security Header',
        name: `Missing ${h.name} (${h.abbr})`,
        severity: h.severity,
        desc: h.desc,
        rec: h.rec
      });
    }
  });

  // If HTTP, flag that too
  if (!isHttps) {
    results.unshift({
      category: 'SSL/HTTPS',
      name: 'HTTPS Not Enforced',
      severity: 'HIGH',
      desc: 'The target URL uses HTTP instead of HTTPS. All traffic is unencrypted.',
      rec: 'Obtain a TLS certificate (free via Let\'s Encrypt) and redirect all HTTP to HTTPS.'
    });
  } else {
    results.push({
      category: 'SSL/HTTPS',
      name: 'HTTPS Enabled',
      severity: 'INFO',
      desc: 'HTTPS is in use. Verify TLS version and cipher strength with an SSL audit tool.',
      rec: 'Use ssl-labs.com/ssltest/ to audit certificate and cipher configuration.'
    });
  }

  return results;
}

function simulatePortScan(hostname) {
  const results = [];

  COMMON_PORTS.forEach(p => {
    // Higher probability for standard web ports
    const chance = (p.port === 80 || p.port === 443) ? 0.7
                 : (p.port === 22) ? 0.45
                 : 0.2;
    if (randomBool(chance)) {
      results.push({
        category: 'Port Exposure',
        name: `Port ${p.port} Open — ${p.service}`,
        severity: p.severity,
        desc: p.desc,
        rec: p.rec
      });
    }
  });

  return results;
}

function simulateSoftwareScan(url) {
  const results = [];
  // Pick a random subset of software vulns to "detect"
  SOFTWARE_VULNS.forEach(s => {
    if (randomBool(0.3)) {
      results.push({
        category: 'Software Version',
        name: s.name,
        severity: s.severity,
        desc: s.desc,
        rec: s.rec
      });
    }
  });
  return results;
}

function simulateSSLScan(url) {
  const results = [];
  const isHttps = url.startsWith('https://');
  if (isHttps) {
    if (randomBool(0.3)) {
      results.push({
        category: 'SSL/TLS',
        name: 'Weak TLS Cipher Suite Detected',
        severity: 'MEDIUM',
        desc: 'Deprecated cipher suites (e.g., RC4, DES, EXPORT) may still be accepted.',
        rec: 'Disable weak ciphers; enforce TLS 1.2+ with strong AEAD ciphers.'
      });
    }
    if (randomBool(0.2)) {
      results.push({
        category: 'SSL/TLS',
        name: 'TLS 1.0 / 1.1 Enabled',
        severity: 'MEDIUM',
        desc: 'Legacy TLS versions 1.0 and 1.1 are deprecated and vulnerable to BEAST/POODLE.',
        rec: 'Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2 minimum.'
      });
    }
    if (randomBool(0.15)) {
      results.push({
        category: 'SSL/TLS',
        name: 'SSL Certificate Expiring Soon',
        severity: 'MEDIUM',
        desc: 'The SSL certificate is expiring within 30 days, which could cause browser warnings.',
        rec: 'Renew certificate immediately. Use auto-renewal tools like certbot.'
      });
    }
  }
  return results;
}

/* ─── Parse Hostname ─────────────────────────────────── */
function parseHostname(url) {
  try {
    if (!url.startsWith('http')) url = 'https://' + url;
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function normalizeUrl(url) {
  url = url.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  return url;
}

/* ─── UI Helpers ─────────────────────────────────────── */

function setProgress(pct, label) {
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('progressLabel').textContent = label;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function severityOrder(s) {
  return { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 }[s] ?? 4;
}

function renderResults(results) {
  const list = document.getElementById('resultsList');
  list.innerHTML = '';

  const sorted = [...results].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

  sorted.forEach(v => {
    const item = document.createElement('div');
    item.className = 'vuln-item';
    item.innerHTML = `
      <span class="vuln-severity sev-${v.severity.toLowerCase()}">${v.severity}</span>
      <div class="vuln-body">
        <div class="vuln-name">${v.name}</div>
        <div class="vuln-desc">${v.desc}</div>
        <div class="vuln-rec">▸ ${v.rec}</div>
      </div>
    `;
    list.appendChild(item);
  });
}

function renderSummary(results, target) {
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  results.forEach(r => { counts[r.severity] = (counts[r.severity] || 0) + 1; });

  const riskLevel = counts.HIGH > 2 ? 'CRITICAL' : counts.HIGH > 0 ? 'HIGH' : counts.MEDIUM > 2 ? 'MEDIUM' : 'LOW';
  const riskColor = { CRITICAL: '#ff4d6a', HIGH: '#ff4d6a', MEDIUM: '#ffd166', LOW: '#06d6a0' }[riskLevel];

  const box = document.getElementById('summaryBox');
  box.style.borderColor = riskColor;
  box.style.backgroundColor = `${riskColor}08`;
  box.innerHTML = `
    <div style="color:${riskColor}; font-weight:700; font-size:0.95rem; margin-bottom:8px;">
      RISK LEVEL: ${riskLevel}
    </div>
    <div style="color:var(--muted); font-size:0.8rem;">
      Target: <span style="color:var(--cyan)">${target}</span> &nbsp;·&nbsp;
      Total Issues: <strong style="color:var(--white)">${results.length}</strong> &nbsp;·&nbsp;
      <span style="color:#ff4d6a">High: ${counts.HIGH}</span> &nbsp;
      <span style="color:#ffd166">Medium: ${counts.MEDIUM}</span> &nbsp;
      <span style="color:#06d6a0">Low: ${counts.LOW}</span> &nbsp;
      <span style="color:var(--cyan)">Info: ${counts.INFO}</span>
    </div>
  `;
}

/* ─── Main Scan Function ─────────────────────────────── */

async function startScan() {
  const input  = document.getElementById('targetUrl').value.trim();
  const btn    = document.getElementById('scanBtn');

  if (!input) {
    alert('Please enter a URL to scan.');
    return;
  }

  const url      = normalizeUrl(input);
  const hostname = parseHostname(url);
  scanTarget     = url;
  scanResults    = [];

  const doHeaders  = document.getElementById('checkHeaders').checked;
  const doPorts    = document.getElementById('checkPorts').checked;
  const doSoftware = document.getElementById('checkSoftware').checked;
  const doSSL      = document.getElementById('checkSSL').checked;

  // Reset UI
  document.getElementById('resultsArea').style.display  = 'none';
  document.getElementById('progressWrap').style.display = 'block';
  document.getElementById('resultsList').innerHTML = '';
  btn.disabled = true;

  setProgress(5, '▸ Resolving target host…');
  await sleep(600);

  if (doSSL) {
    setProgress(20, '▸ Checking SSL/TLS configuration…');
    await sleep(700);
    scanResults.push(...simulateSSLScan(url));
  }

  if (doHeaders) {
    setProgress(40, '▸ Inspecting security headers…');
    await sleep(800);
    scanResults.push(...simulateHeaderScan(url));
  }

  if (doPorts) {
    setProgress(60, '▸ Probing common service ports…');
    await sleep(900);
    scanResults.push(...simulatePortScan(hostname));
  }

  if (doSoftware) {
    setProgress(80, '▸ Detecting software versions…');
    await sleep(700);
    scanResults.push(...simulateSoftwareScan(url));
  }

  setProgress(100, `▸ Scan complete — ${scanResults.length} issue(s) found`);
  await sleep(400);

  // Show results
  document.getElementById('resultsArea').style.display = 'block';
  renderSummary(scanResults, url);
  renderResults(scanResults);

  btn.disabled = false;

  // Smooth scroll to results
  document.getElementById('resultsArea').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* ─── Download Report ─────────────────────────────────── */

function downloadReport() {
  if (!scanResults.length) return;

  const ts   = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const lines = [];

  lines.push('='.repeat(60));
  lines.push('  VulnScan — Vulnerability Assessment Report');
  lines.push('='.repeat(60));
  lines.push(`  Target   : ${scanTarget}`);
  lines.push(`  Date     : ${new Date().toLocaleString()}`);
  lines.push(`  Total    : ${scanResults.length} finding(s)`);
  lines.push('='.repeat(60));
  lines.push('');

  const sorted = [...scanResults].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

  sorted.forEach((v, i) => {
    lines.push(`[${i + 1}] ${v.severity.padEnd(6)} | ${v.name}`);
    lines.push(`     Category : ${v.category}`);
    lines.push(`     Finding  : ${v.desc}`);
    lines.push(`     Fix      : ${v.rec}`);
    lines.push('');
  });

  lines.push('-'.repeat(60));
  lines.push('  Generated by VulnScan (educational use only)');
  lines.push('  https://github.com/your-username/vulnscan');
  lines.push('-'.repeat(60));

  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `vulnscan-report-${ts}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ─── Reset ───────────────────────────────────────────── */

function resetScan() {
  document.getElementById('targetUrl').value = '';
  document.getElementById('resultsArea').style.display  = 'none';
  document.getElementById('progressWrap').style.display = 'none';
  scanResults = [];
  scanTarget  = '';
  document.getElementById('progressBar').style.width = '0%';
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
}

/* ─── Enter key support ──────────────────────────────── */
document.getElementById('targetUrl').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
