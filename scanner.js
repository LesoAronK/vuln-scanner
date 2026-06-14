'use strict';

/* ── Vulnerability Database ─────────────────────────── */
const DB = {
  headers: [
    {name:'Content-Security-Policy (CSP)',sev:'CRITICAL',cat:'Security Header',
     desc:'No Content-Security-Policy header detected. This allows attackers to inject malicious scripts (XSS) that execute in the context of your site, stealing cookies, session tokens, and user data.',
     fix:'Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:',
     cves:['CVE-2023-25690','CVE-2022-31813']},
    {name:'Strict-Transport-Security (HSTS)',sev:'HIGH',cat:'Security Header',
     desc:'Missing HSTS header. Browsers may allow HTTP connections, enabling SSL-stripping attacks. Attackers on the same network can intercept and modify unencrypted traffic in real time.',
     fix:'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
     cves:['CVE-2021-43527']},
    {name:'X-Frame-Options',sev:'HIGH',cat:'Security Header',
     desc:'Missing X-Frame-Options enables clickjacking. Attackers embed your site in an invisible iframe and trick users into clicking buttons — triggering unauthorized account actions.',
     fix:'X-Frame-Options: DENY\n(or use CSP frame-ancestors directive instead)',
     cves:['CVE-2022-0847']},
    {name:'X-Content-Type-Options',sev:'MEDIUM',cat:'Security Header',
     desc:'Missing X-Content-Type-Options allows MIME-sniffing. Browsers may execute uploaded files as scripts by guessing their type rather than reading the declared Content-Type.',
     fix:'X-Content-Type-Options: nosniff',cves:[]},
    {name:'Referrer-Policy',sev:'LOW',cat:'Security Header',
     desc:'No Referrer-Policy set. The full URL is sent as the Referer header to third-party sites, potentially leaking sensitive URL parameters such as auth tokens or session IDs.',
     fix:'Referrer-Policy: strict-origin-when-cross-origin',cves:[]},
    {name:'Permissions-Policy',sev:'LOW',cat:'Security Header',
     desc:'No Permissions-Policy header. Third-party scripts and embedded iframes can access browser APIs (camera, microphone, geolocation) without any restriction.',
     fix:'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',cves:[]},
  ],
  ports: [
    {name:'FTP service on port 21',sev:'CRITICAL',cat:'Port Exposure',
     desc:'FTP transmits credentials and files in plaintext. Any attacker with network access can capture usernames, passwords, and all data. FTP is also vulnerable to bounce and brute-force attacks.',
     fix:'Disable FTP. Use SFTP (SSH port 22) or FTPS with TLS. Block port 21 at the firewall.',
     cves:['CVE-2021-45046','CVE-2020-9484']},
    {name:'Telnet on port 23 (plaintext)',sev:'CRITICAL',cat:'Port Exposure',
     desc:'Telnet transmits everything including passwords in plaintext. This should never be internet-facing. Attackers regularly scan for and exploit exposed Telnet services for initial access.',
     fix:'Disable Telnet entirely. Use SSH (port 22). Block port 23 at the firewall.',
     cves:['CVE-2019-0708']},
    {name:'SSH on default port 22',sev:'MEDIUM',cat:'Port Exposure',
     desc:'SSH is open on the default port. While SSH itself is secure, port 22 is probed constantly — Shodan reports millions of daily brute-force attempts against default-port SSH.',
     fix:'Change to a non-standard port. Disable password auth and require SSH keys. Consider fail2ban.',
     cves:['CVE-2023-38408']},
    {name:'MySQL on port 3306 (public)',sev:'CRITICAL',cat:'Port Exposure',
     desc:'MySQL is publicly accessible. Direct database exposure causes mass data breaches. Attackers can brute-force credentials or exploit authentication bypass vulnerabilities.',
     fix:'Bind MySQL to 127.0.0.1 in mysqld.cnf. Block port 3306 externally with firewall rules.',
     cves:['CVE-2023-21980','CVE-2022-21595']},
    {name:'Redis on port 6379 (no auth)',sev:'CRITICAL',cat:'Port Exposure',
     desc:'Redis is publicly accessible. With no auth by default, attackers can read all data, write arbitrary values, and achieve RCE by writing SSH authorized_keys or cron jobs.',
     fix:'Bind to 127.0.0.1 in redis.conf. Set requirepass. Block port 6379 at firewall.',
     cves:['CVE-2022-0543']},
    {name:'MongoDB on port 27017 (public)',sev:'CRITICAL',cat:'Port Exposure',
     desc:'MongoDB is publicly accessible. The "MongoDB apocalypse" wiped thousands of unprotected databases. Older versions have no authentication enabled by default.',
     fix:'Enable MongoDB authentication. Bind to localhost. Block port 27017 externally.',
     cves:['CVE-2021-20328']},
    {name:'HTTP on port 8080',sev:'MEDIUM',cat:'Port Exposure',
     desc:'Port 8080 is open — commonly an admin panel, dev server, or proxy. If this is an admin interface, it must not be publicly reachable.',
     fix:'Restrict port 8080 to allowlisted IPs via firewall rules.',cves:[]},
  ],
  software: [
    {name:'Apache version in Server header',sev:'HIGH',cat:'Software Version',
     desc:'The Server header reveals the Apache version (e.g. Apache/2.4.49). Attackers use this fingerprint to look up exact CVEs. Apache 2.4.49-50 had a path traversal RCE scored CVSS 9.8.',
     fix:'Set in httpd.conf:\nServerTokens Prod\nServerSignature Off',
     cves:['CVE-2021-41773','CVE-2021-42013']},
    {name:'PHP version in X-Powered-By',sev:'HIGH',cat:'Software Version',
     desc:'X-Powered-By reveals the PHP version. PHP 7.x is end-of-life with no security patches. Known unpatched vulnerabilities include RCE via deserialization and type-juggling bugs.',
     fix:'Set in php.ini:\nexpose_php = Off\nUpgrade to PHP 8.2+ (actively maintained).',
     cves:['CVE-2022-31628','CVE-2021-21705']},
    {name:'WordPress version detectable',sev:'HIGH',cat:'Software Version',
     desc:'WordPress version is exposed via <meta name="generator"> or readme.html. Versions below 6.4 have known SQL injection, XSS, and authenticated RCE vulnerabilities.',
     fix:'Remove generator meta tag. Delete readme.html and license.txt. Keep core, themes, and plugins updated.',
     cves:['CVE-2023-39999','CVE-2022-3590']},
    {name:'nginx version in Server header',sev:'MEDIUM',cat:'Software Version',
     desc:'nginx version is visible in Server header, giving attackers a precise fingerprint for researching version-specific vulnerabilities and timing attacks.',
     fix:'Add to nginx.conf http{} block:\nserver_tokens off;',
     cves:['CVE-2021-23017']},
    {name:'Stack disclosure via X-Powered-By',sev:'LOW',cat:'Software Version',
     desc:'X-Powered-By or similar headers reveal the full technology stack (e.g. Express, Laravel, Django). This reduces attacker reconnaissance effort significantly.',
     fix:'Remove at server or application level:\nnginx: proxy_hide_header X-Powered-By;\nExpress: app.disable(\'x-powered-by\')',cves:[]},
  ],
  ssl: [
    {name:'TLS 1.0 / 1.1 still accepted',sev:'HIGH',cat:'SSL / TLS',
     desc:'Server accepts deprecated TLS 1.0/1.1. TLS 1.0 is vulnerable to BEAST and POODLE attacks. PCI DSS mandated disabling TLS 1.0 in June 2018.',
     fix:'nginx: ssl_protocols TLSv1.2 TLSv1.3;\nApache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nRef: ssl-config.mozilla.org',
     cves:['CVE-2014-3566','CVE-2011-3389']},
    {name:'Weak cipher suites (RC4/DES)',sev:'HIGH',cat:'SSL / TLS',
     desc:'Server accepts weak or broken ciphers such as RC4, DES, or NULL ciphers. These can be cracked in real time by well-resourced attackers, exposing encrypted session data.',
     fix:'nginx: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!RC4:!DES;\nUse ssl-config.mozilla.org for a full hardened config.',
     cves:['CVE-2013-2566','CVE-2015-2808']},
    {name:'SSL certificate expiring in <30 days',sev:'MEDIUM',cat:'SSL / TLS',
     desc:'SSL certificate expires within 30 days. Expired certificates trigger browser security warnings for all visitors and will break API clients and webhooks that validate certificates.',
     fix:'Renew now:\ncertbot renew --cert-name your-domain.com\nEnable auto-renewal: add certbot renew to a daily cron job.',
     cves:[]},
    {name:'HTTP not redirected to HTTPS',sev:'HIGH',cat:'SSL / TLS',
     desc:'Site is accessible over plain HTTP without a redirect to HTTPS. Session cookies and form submissions are sent unencrypted, enabling man-in-the-middle interception.',
     fix:'nginx:\nreturn 301 https://$host$request_uri;\nApache:\nRewriteEngine On\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
     cves:[]},
  ],
  misc: [
    {name:'Directory listing enabled',sev:'HIGH',cat:'Misconfiguration',
     desc:'Web server directory listing is enabled. Attackers can browse the file system, discovering backup files, config files, SQL dumps, and source code.',
     fix:'nginx: autoindex off;\nApache in .htaccess: Options -Indexes',cves:[]},
    {name:'Debug mode enabled in production',sev:'CRITICAL',cat:'Misconfiguration',
     desc:'Application is running in debug mode. This exposes full stack traces, environment variables (including secrets and DB credentials), and source code snippets to anyone who triggers an error.',
     fix:'Set DEBUG=False in all production config.\nEnsure generic error pages are shown to end users.',
     cves:['CVE-2021-25281']},
    {name:'robots.txt leaks sensitive paths',sev:'LOW',cat:'Misconfiguration',
     desc:'robots.txt Disallow entries reveal admin paths, backup URLs, or internal directories. Attackers read robots.txt specifically to discover hidden endpoints that are being "protected by obscurity".',
     fix:'Remove sensitive paths from robots.txt Disallow entries — their presence advertises them. Protect paths with authentication instead.',cves:[]},
    {name:'CORS wildcard with credentials',sev:'HIGH',cat:'Misconfiguration',
     desc:'Access-Control-Allow-Origin: * combined with credentials enabled allows any website to make authenticated cross-origin requests to your API, enabling account takeover via CSRF.',
     fix:'Restrict to known origins:\nAccess-Control-Allow-Origin: https://yourdomain.com\nNever combine credentials:true with wildcard origin.',
     cves:['CVE-2020-11023']},
    {name:'.git directory publicly accessible',sev:'CRITICAL',cat:'Misconfiguration',
     desc:'The .git directory can be downloaded via the browser. Attackers can reconstruct your full source code history and find hardcoded secrets, API keys, and database credentials committed in the past.',
     fix:'nginx: location ~ /\\.git { deny all; return 404; }\nOr move web root above the git repository.',cves:[]},
  ]
};

/* ── State ──────────────────────────────────────────── */
let allResults = [];
let activeFilter = 'ALL';
const SEV_ORDER = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};

/* ── Helpers ────────────────────────────────────────── */
function coin(p){ return Math.random() < p; }
function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }
function sortBySev(arr){ return [...arr].sort((a,b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]); }

/* ── Scan Simulation ────────────────────────────────── */
function runChecks(url){
  const https = url.startsWith('https://');
  const results = [];
  const o = {
    h:   document.getElementById('chkHeaders').checked,
    p:   document.getElementById('chkPorts').checked,
    s:   document.getElementById('chkSoftware').checked,
    ssl: document.getElementById('chkSSL').checked,
    m:   document.getElementById('chkMisc').checked
  };

  if(o.h) DB.headers.forEach(item => {
    const base = item.sev==='CRITICAL'?0.65:item.sev==='HIGH'?0.55:item.sev==='MEDIUM'?0.5:0.4;
    if(coin(https ? base-0.1 : base+0.1)) results.push({...item});
  });

  if(o.p) DB.ports.forEach(item => {
    const base = item.name.includes('SSH')?0.4:item.sev==='CRITICAL'?0.28:0.32;
    if(coin(base)) results.push({...item});
  });

  if(o.s) DB.software.forEach(item => {
    if(coin(0.42)) results.push({...item});
  });

  if(o.ssl){
    if(!https) results.push({...DB.ssl[3]});
    DB.ssl.slice(0,3).forEach(item => { if(coin(0.35)) results.push({...item}); });
  }

  if(o.m) DB.misc.forEach(item => {
    if(coin(0.3)) results.push({...item});
  });

  return results;
}

/* ── Progress Steps ─────────────────────────────────── */
const STEPS = [
  'Resolving DNS and host information',
  'Checking SSL/TLS configuration',
  'Probing HTTP security headers',
  'Testing port exposure',
  'Detecting software versions',
  'Scanning for misconfigurations',
  'Compiling vulnerability report'
];

async function startScan(){
  let url = document.getElementById('urlInput').value.trim();
  if(!url){ alert('Enter a URL to scan.'); return; }
  if(!url.startsWith('http')) url = 'https://' + url;

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('results').style.display = 'none';
  const prog = document.getElementById('progSection');
  prog.style.display = 'block';

  const stepsEl = document.getElementById('progSteps');
  stepsEl.innerHTML = STEPS.map((s,i) => `
    <div class="prog-step" id="ps${i}">
      <div class="step-dot" id="pd${i}"></div>
      <span>${s}</span>
    </div>`).join('');

  const bar = document.getElementById('progBar');
  bar.style.width = '0%';

  for(let i=0; i<STEPS.length; i++){
    const step = document.getElementById('ps'+i);
    const dot  = document.getElementById('pd'+i);
    step.classList.add('active');
    dot.className = 'step-dot spin';
    dot.innerHTML = '<i class="ti ti-loader-2" style="font-size:9px;animation:spin .7s linear infinite"></i>';
    bar.style.width = Math.round((i / STEPS.length) * 94) + '%';
    await sleep(Math.floor(Math.random()*350)+300);
    step.classList.remove('active');
    step.classList.add('done');
    dot.className = 'step-dot ok';
    dot.innerHTML = '<i class="ti ti-check" style="font-size:9px"></i>';
  }
  bar.style.width = '100%';
  await sleep(180);

  allResults = sortBySev(runChecks(url));
  activeFilter = 'ALL';
  showResults(url);
  prog.style.display = 'none';
  document.getElementById('scanBtn').disabled = false;
}

/* ── Render Results ─────────────────────────────────── */
function showResults(url){
  const res = document.getElementById('results');
  res.style.display = 'block';

  const c = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  allResults.forEach(r => c[r.sev] = (c[r.sev]||0)+1);
  const total = allResults.length;

  document.getElementById('summaryGrid').innerHTML = `
    <div class="stat"><div class="stat-label">Total</div><div class="stat-value">${total}</div></div>
    <div class="stat"><div class="stat-label">Critical</div><div class="stat-value red">${c.CRITICAL}</div></div>
    <div class="stat"><div class="stat-label">High</div><div class="stat-value amb">${c.HIGH}</div></div>
    <div class="stat"><div class="stat-label">Medium</div><div class="stat-value blu">${c.MEDIUM}</div></div>
    <div class="stat"><div class="stat-label">Low</div><div class="stat-value grn">${c.LOW}</div></div>
  `;

  const lvl = c.CRITICAL>0?'CRITICAL':c.HIGH>2?'HIGH':c.HIGH>0?'MEDIUM':'LOW';
  const cfg = {
    CRITICAL:{bg:'rgba(244,63,94,.1)',col:'#f87171',bdr:'rgba(244,63,94,.3)',icon:'ti-alert-octagon',msg:'Critical risk — immediate remediation required'},
    HIGH:    {bg:'rgba(245,158,11,.08)',col:'#fbbf24',bdr:'rgba(245,158,11,.3)',icon:'ti-alert-triangle',msg:'High risk — address vulnerabilities promptly'},
    MEDIUM:  {bg:'rgba(59,130,246,.08)',col:'#60a5fa',bdr:'rgba(59,130,246,.25)',icon:'ti-info-circle',msg:'Medium risk — review and remediate findings'},
    LOW:     {bg:'rgba(16,185,129,.08)',col:'#34d399',bdr:'rgba(16,185,129,.25)',icon:'ti-circle-check',msg:'Low risk — minor improvements recommended'},
  }[lvl];

  const hostname = (() => { try { return new URL(url).hostname; } catch{ return url; } })();
  const banner = document.getElementById('riskBanner');
  banner.style.cssText = `background:${cfg.bg};border-color:${cfg.bdr};color:${cfg.col};border:1px solid ${cfg.bdr}`;
  banner.innerHTML = `<i class="ti ${cfg.icon}"></i><span>${cfg.msg} — <strong>${hostname}</strong></span>`;

  renderFilterBtns(c);
  renderFindings();
  res.scrollIntoView({behavior:'smooth', block:'nearest'});
}

function renderFilterBtns(c){
  const filters = ['ALL', ...Object.keys(SEV_ORDER).filter(s => (c[s]||0)>0)];
  document.getElementById('filterBtns').innerHTML = filters.map(f =>
    `<button class="f-btn${f===activeFilter?' on':''}" onclick="setFilter('${f}')">${f==='ALL'?'All':f}</button>`
  ).join('');
}

function setFilter(f){
  activeFilter = f;
  document.querySelectorAll('.f-btn').forEach(b => {
    const label = b.textContent.trim();
    b.classList.toggle('on', label===f || (f==='ALL' && label==='All'));
  });
  renderFindings();
}

function renderFindings(){
  const list   = document.getElementById('findingsList');
  const filtered = activeFilter==='ALL' ? allResults : allResults.filter(r => r.sev===activeFilter);
  document.getElementById('findingsTitle').textContent = `${filtered.length} finding${filtered.length!==1?'s':''}`;

  if(!filtered.length){
    list.innerHTML = `<div style="text-align:center;padding:2rem;color:var(--muted);font-size:.85rem">No findings for this filter.</div>`;
    return;
  }

  list.innerHTML = filtered.map((v,i) => `
    <div class="finding" onclick="toggleFinding(${i})">
      <div class="finding-head">
        <span class="badge b-${v.sev}">${v.sev}</span>
        <span class="finding-name">${v.name}</span>
        <span class="finding-cat">${v.cat}</span>
        <i class="ti ti-chevron-down finding-chev" id="chev${i}"></i>
      </div>
      <div class="finding-body" id="body${i}">
        <p class="finding-desc">${v.desc}</p>
        <div class="fix-label">Remediation</div>
        <div class="fix-block">${v.fix.replace(/\n/g,'<br>')}</div>
        ${v.cves&&v.cves.length ? `<div class="cve-row">${v.cves.map(c=>`<a class="cve-tag" href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank">${c}</a>`).join('')}</div>` : ''}
      </div>
    </div>
  `).join('');
}

function toggleFinding(i){
  const body = document.getElementById('body'+i);
  const chev = document.getElementById('chev'+i);
  const open = body.classList.toggle('open');
  chev.classList.toggle('open', open);
}

/* ── Reset ──────────────────────────────────────────── */
function resetScan(){
  document.getElementById('urlInput').value = '';
  document.getElementById('results').style.display = 'none';
  document.getElementById('progSection').style.display = 'none';
  allResults = [];
}

/* ── Report Downloads ───────────────────────────────── */
function downloadTxt(){
  if(!allResults.length) return;
  const url = document.getElementById('urlInput').value.trim();
  const ts  = new Date().toLocaleString();
  const c   = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  allResults.forEach(r => c[r.sev]=(c[r.sev]||0)+1);
  const lvl = c.CRITICAL>0?'CRITICAL':c.HIGH>2?'HIGH':'MEDIUM';

  const lines = [
    '='.repeat(68),
    '  VULNSCAN — VULNERABILITY ASSESSMENT REPORT',
    '='.repeat(68),
    `  Target    : ${url}`,
    `  Scan Date : ${ts}`,
    `  Findings  : ${allResults.length} total  |  Critical: ${c.CRITICAL}  High: ${c.HIGH}  Medium: ${c.MEDIUM}  Low: ${c.LOW}`,
    `  Risk Level: ${lvl}`,
    '='.repeat(68), ''
  ];

  sortBySev(allResults).forEach((v,i) => {
    lines.push(`[${String(i+1).padStart(2,'0')}] ${v.sev.padEnd(9)} ${v.name}`);
    lines.push(`      Category    : ${v.cat}`);
    lines.push(`      Description :`);
    lines.push(`        ${v.desc}`);
    lines.push(`      Remediation :`);
    v.fix.split('\n').forEach(l => lines.push(`        ${l}`));
    if(v.cves&&v.cves.length) lines.push(`      CVE Refs    : ${v.cves.join(' | ')}`);
    lines.push('');
  });

  lines.push('-'.repeat(68));
  lines.push('  Generated by VulnScan — https://github.com/your-username/vulnscan');
  lines.push('  For educational use only. Always obtain proper authorization.');
  lines.push('-'.repeat(68));

  const blob = new Blob([lines.join('\n')], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vulnscan-report-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function downloadJSON(){
  if(!allResults.length) return;
  const url = document.getElementById('urlInput').value.trim();
  const c   = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  allResults.forEach(r => c[r.sev]=(c[r.sev]||0)+1);

  const report = {
    meta: { tool:'VulnScan', version:'1.0', generated: new Date().toISOString(), target: url },
    summary: { total: allResults.length, ...c, riskLevel: c.CRITICAL>0?'CRITICAL':c.HIGH>2?'HIGH':'MEDIUM' },
    findings: sortBySev(allResults).map((v,i) => ({
      id: i+1, severity: v.sev, category: v.cat, name: v.name,
      description: v.desc, remediation: v.fix, cve_references: v.cves||[]
    }))
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vulnscan-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ── Enter key ──────────────────────────────────────── */
document.getElementById('urlInput').addEventListener('keydown', e => {
  if(e.key === 'Enter') startScan();
});
