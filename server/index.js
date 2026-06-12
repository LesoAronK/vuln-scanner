const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");

const app = express();
const PORT = process.env.PORT || 5000;
const REPORTS_DIR = path.join(__dirname, "../reports");

if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

app.use(cors());
app.use(express.json());
app.use("/reports", express.static(REPORTS_DIR));

if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.join(__dirname, "../client/build")));
}

// ─── Scan profiles ──────────────────────────────────────────────────────────
const SCAN_PROFILES = {
  quick: {
    label: "Quick Scan",
    args: "-T4 -F --open",
    desc: "Fast scan of top 100 ports",
  },
  standard: {
    label: "Standard Scan",
    args: "-sV -sC -T4 -p 1-1000",
    desc: "Service/version detection on top 1000 ports",
  },
  full: {
    label: "Full Port Scan",
    args: "-sV -sC -T4 -p-",
    desc: "All 65535 ports with service/version detection",
  },
  vuln: {
    label: "Vulnerability Scan",
    args: "-sV -sC --script=vuln -T4",
    desc: "NSE vulnerability scripts on common ports",
  },
  udp: {
    label: "UDP Scan",
    args: "-sU -sV -T4 --top-ports 200",
    desc: "Top 200 UDP ports",
  },
  stealth: {
    label: "Stealth SYN Scan",
    args: "-sS -sV -T3 -p 1-1000",
    desc: "SYN stealth scan (requires root/sudo)",
  },
  os: {
    label: "OS Detection",
    args: "-O -sV -T4",
    desc: "Attempt OS fingerprinting (requires root/sudo)",
  },
  aggressive: {
    label: "Aggressive Scan",
    args: "-A -T4",
    desc: "OS + version + scripts + traceroute",
  },
  ping: {
    label: "Ping Sweep",
    args: "-sn",
    desc: "Host discovery only, no port scan",
  },
  firewall: {
    label: "Firewall Evasion",
    args: "-sA -T4 -p 1-1000",
    desc: "ACK scan to map firewall rules",
  },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
function sanitizeTarget(target) {
  // Allow IPs, CIDR ranges, hostnames
  const valid = /^[a-zA-Z0-9.\-_/]+$/;
  return valid.test(target) ? target : null;
}

function severityFromPort(port, service, state) {
  if (state !== "open") return "info";
  const critical = [21, 23, 25, 445, 3389, 5900, 1433, 3306, 5432, 27017];
  const high = [22, 80, 443, 8080, 8443, 110, 143, 53, 161];
  const p = parseInt(port);
  if (critical.includes(p)) return "critical";
  if (high.includes(p)) return "high";
  return "medium";
}

function serviceRisk(service, version) {
  const findings = [];
  const s = (service || "").toLowerCase();
  const v = (version || "").toLowerCase();

  if (s.includes("ftp")) findings.push({ issue: "FTP service exposed", detail: "FTP transmits credentials in plaintext. Use SFTP/SCP instead.", severity: "critical" });
  if (s.includes("telnet")) findings.push({ issue: "Telnet service exposed", detail: "Telnet is unencrypted. Replace with SSH immediately.", severity: "critical" });
  if (s.includes("smtp") || s.includes("pop3") || s.includes("imap")) findings.push({ issue: "Mail service detected", detail: "Ensure TLS/STARTTLS is enforced and relay is restricted.", severity: "high" });
  if (s.includes("vnc") || s.includes("rdp")) findings.push({ issue: "Remote desktop service exposed", detail: "Remote access services are frequent attack vectors. Restrict to VPN.", severity: "critical" });
  if (s.includes("mysql") || s.includes("postgres") || s.includes("mongodb") || s.includes("mssql")) findings.push({ issue: "Database service exposed publicly", detail: "Database ports should never be exposed to the internet. Use firewall rules.", severity: "critical" });
  if (s.includes("smb") || s.includes("netbios")) findings.push({ issue: "SMB/NetBIOS exposed", detail: "SMB vulnerabilities (EternalBlue/MS17-010) are highly exploitable.", severity: "critical" });
  if (s.includes("snmp")) findings.push({ issue: "SNMP service detected", detail: "Default SNMP community strings (public/private) are often unchanged.", severity: "high" });
  if (s.includes("http") && !s.includes("https")) findings.push({ issue: "Unencrypted HTTP detected", detail: "Use HTTPS with a valid TLS certificate.", severity: "medium" });

  // Version-based checks
  if (v.match(/apache\/2\.[0-3]\./)) findings.push({ issue: "Potentially outdated Apache version", detail: `Detected: ${version}. Upgrade to latest stable release.`, severity: "high" });
  if (v.match(/openssh_[1-7]\./)) findings.push({ issue: "Potentially outdated OpenSSH", detail: `Detected: ${version}. Older versions may have known CVEs.`, severity: "medium" });
  if (v.match(/nginx\/1\.[0-9]\./)) findings.push({ issue: "Potentially outdated Nginx", detail: `Detected: ${version}. Verify against current CVE databases.`, severity: "medium" });

  return findings;
}

function parseNmapXML(xmlStr) {
  const results = { hosts: [], summary: "" };
  try {
    // Extract host blocks
    const hostMatches = xmlStr.matchAll(/<host[^>]*>([\s\S]*?)<\/host>/g);
    for (const hm of hostMatches) {
      const block = hm[1];
      const addrMatch = block.match(/<address addr="([^"]+)" addrtype="ipv4"/);
      const hostnameMatch = block.match(/<hostname name="([^"]+)"/);
      const statusMatch = block.match(/<status state="([^"]+)"/);

      if (!addrMatch) continue;
      const host = {
        ip: addrMatch[1],
        hostname: hostnameMatch ? hostnameMatch[1] : "",
        status: statusMatch ? statusMatch[1] : "unknown",
        ports: [],
        findings: [],
        osGuess: "",
      };

      // OS detection
      const osMatch = block.match(/<osmatch name="([^"]+)" accuracy="(\d+)"/);
      if (osMatch) host.osGuess = `${osMatch[1]} (${osMatch[2]}% confidence)`;

      // Ports
      const portMatches = block.matchAll(/<port protocol="([^"]+)" portid="(\d+)">([\s\S]*?)<\/port>/g);
      for (const pm of portMatches) {
        const pBlock = pm[3];
        const stateMatch = pBlock.match(/<state state="([^"]+)"/);
        const serviceMatch = pBlock.match(/<service name="([^"]*)"[^>]*product="([^"]*)"[^>]*version="([^"]*)"/);
        const serviceSimple = pBlock.match(/<service name="([^"]*)"/);

        const state = stateMatch ? stateMatch[1] : "unknown";
        const serviceName = serviceMatch ? serviceMatch[1] : (serviceSimple ? serviceSimple[1] : "unknown");
        const product = serviceMatch ? serviceMatch[2] : "";
        const version = serviceMatch ? serviceMatch[3] : "";
        const fullVersion = [product, version].filter(Boolean).join(" ");

        // Script outputs
        const scriptMatches = [...pBlock.matchAll(/<script id="([^"]+)" output="([^"]+)"/g)];
        const scripts = scriptMatches.map((s) => ({ id: s[1], output: s[2].replace(/\\n/g, " ").substring(0, 300) }));

        const portEntry = {
          protocol: pm[1],
          port: pm[2],
          state,
          service: serviceName,
          version: fullVersion,
          severity: severityFromPort(pm[2], serviceName, state),
          scripts,
        };

        host.ports.push(portEntry);
        host.findings.push(...serviceRisk(serviceName, fullVersion));

        // Script-based vulns
        for (const sc of scripts) {
          if (sc.id.startsWith("vuln") || sc.output.toLowerCase().includes("vulnerable")) {
            host.findings.push({
              issue: `Vulnerability detected via NSE: ${sc.id}`,
              detail: sc.output,
              severity: "critical",
            });
          }
        }
      }

      results.hosts.push(host);
    }

    // Summary
    const runMatch = xmlStr.match(/summary="([^"]+)"/);
    if (runMatch) results.summary = runMatch[1];
  } catch (e) {
    results.error = e.message;
  }
  return results;
}

// ─── Generate PDF ─────────────────────────────────────────────────────────────
function generatePDF(scanData, filePath) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: "A4" });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    const colors = { bg: "#0d1117", accent: "#58a6ff", critical: "#f85149", high: "#ff7b72", medium: "#e3b341", low: "#3fb950", info: "#8b949e" };

    // Header
    doc.rect(0, 0, doc.page.width, 120).fill("#0d1117");
    doc.fontSize(26).fillColor("#58a6ff").font("Helvetica-Bold").text("VULNERABILITY SCAN REPORT", 50, 35);
    doc.fontSize(10).fillColor("#8b949e").font("Helvetica").text(`Generated: ${new Date().toUTCString()}`, 50, 68);
    doc.text(`Target: ${scanData.target}  |  Profile: ${scanData.profileLabel}`, 50, 83);
    doc.moveDown(3);

    // Stats bar
    const { hosts } = scanData.parsed;
    let totalPorts = 0, totalFindings = 0, criticalCount = 0;
    hosts.forEach((h) => {
      totalPorts += h.ports.filter((p) => p.state === "open").length;
      totalFindings += h.findings.length;
      criticalCount += h.findings.filter((f) => f.severity === "critical").length;
    });

    doc.fillColor("#1c2128").rect(50, doc.y, doc.page.width - 100, 60).fill();
    const statsY = doc.y + 8;
    const stats = [
      { label: "Hosts", value: hosts.length },
      { label: "Open Ports", value: totalPorts },
      { label: "Findings", value: totalFindings },
      { label: "Critical", value: criticalCount },
    ];
    stats.forEach((s, i) => {
      const x = 70 + i * 120;
      doc.fontSize(20).fillColor(i === 3 && criticalCount > 0 ? "#f85149" : "#58a6ff").font("Helvetica-Bold").text(String(s.value), x, statsY + 5, { width: 100 });
      doc.fontSize(9).fillColor("#8b949e").font("Helvetica").text(s.label, x, statsY + 32, { width: 100 });
    });
    doc.moveDown(5);

    // Per host
    hosts.forEach((host, idx) => {
      if (doc.y > 680) doc.addPage();
      doc.fontSize(14).fillColor("#58a6ff").font("Helvetica-Bold").text(`Host ${idx + 1}: ${host.ip}${host.hostname ? " (" + host.hostname + ")" : ""}`, 50, doc.y);
      doc.fontSize(9).fillColor("#8b949e").font("Helvetica").text(`Status: ${host.status}${host.osGuess ? "  |  OS: " + host.osGuess : ""}`, 50, doc.y + 2);
      doc.moveDown(0.5);

      // Ports table
      const openPorts = host.ports.filter((p) => p.state === "open");
      if (openPorts.length > 0) {
        doc.fontSize(10).fillColor("#e6edf3").font("Helvetica-Bold").text("Open Ports", 50, doc.y);
        doc.moveDown(0.3);

        // Table header
        doc.fillColor("#161b22").rect(50, doc.y, doc.page.width - 100, 18).fill();
        const cols = [60, 100, 160, 270, 400];
        const headers = ["Port", "Proto", "Service", "Version", "Risk"];
        headers.forEach((h, i) => doc.fontSize(8).fillColor("#8b949e").font("Helvetica-Bold").text(h, cols[i], doc.y + 4));
        doc.moveDown(1.2);

        openPorts.forEach((p) => {
          if (doc.y > 720) doc.addPage();
          const rowY = doc.y;
          const sevColor = colors[p.severity] || colors.info;
          doc.fontSize(8).fillColor("#e6edf3").font("Helvetica").text(p.port, cols[0], rowY);
          doc.text(p.protocol, cols[1], rowY);
          doc.text(p.service, cols[2], rowY);
          doc.text((p.version || "-").substring(0, 40), cols[3], rowY);
          doc.fillColor(sevColor).text(p.severity.toUpperCase(), cols[4], rowY);
          doc.moveDown(0.8);
        });
      }

      // Findings
      if (host.findings.length > 0) {
        doc.moveDown(0.5);
        doc.fontSize(10).fillColor("#e6edf3").font("Helvetica-Bold").text("Security Findings", 50, doc.y);
        doc.moveDown(0.3);
        host.findings.forEach((f) => {
          if (doc.y > 700) doc.addPage();
          const sevColor = colors[f.severity] || colors.info;
          doc.fillColor(sevColor).fontSize(8).font("Helvetica-Bold").text(`[${f.severity.toUpperCase()}] ${f.issue}`, 60, doc.y);
          doc.fillColor("#8b949e").fontSize(7.5).font("Helvetica").text(f.detail, 70, doc.y + 1, { width: doc.page.width - 140 });
          doc.moveDown(1.2);
        });
      }

      if (openPorts.length === 0 && host.findings.length === 0) {
        doc.fillColor("#3fb950").fontSize(9).font("Helvetica").text("No open ports or findings detected.", 60, doc.y);
      }

      doc.moveDown(1);
      doc.strokeColor("#21262d").lineWidth(1).moveTo(50, doc.y).lineTo(doc.page.width - 50, doc.y).stroke();
      doc.moveDown(1);
    });

    // Recommendations
    if (doc.y > 600) doc.addPage();
    doc.moveDown(0.5);
    doc.fontSize(13).fillColor("#58a6ff").font("Helvetica-Bold").text("General Recommendations", 50, doc.y);
    doc.moveDown(0.5);
    const recs = [
      "Close or firewall all ports not required for the application to function.",
      "Replace insecure protocols (FTP, Telnet, HTTP) with encrypted alternatives (SFTP, SSH, HTTPS).",
      "Move database services behind private network interfaces — never expose them publicly.",
      "Keep all software (OS, web server, frameworks) patched to the latest stable versions.",
      "Implement intrusion detection/prevention systems (IDS/IPS) on perimeter networks.",
      "Restrict remote access services to VPN-only access with MFA enforced.",
      "Run regular authenticated scans and integrate into your CI/CD security pipeline.",
      "Review SNMP community strings and disable SNMP v1/v2 if not needed.",
    ];
    recs.forEach((r) => {
      doc.fontSize(8).fillColor("#e6edf3").font("Helvetica").text(`• ${r}`, 60, doc.y, { width: doc.page.width - 120 });
      doc.moveDown(0.7);
    });

    // Footer
    doc.fontSize(7).fillColor("#484f58").font("Helvetica").text("This report is for authorized security testing only. Unauthorized scanning is illegal. Use responsibly.", 50, doc.page.height - 40, { align: "center", width: doc.page.width - 100 });

    doc.end();
    stream.on("finish", resolve);
    stream.on("error", reject);
  });
}

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get("/api/profiles", (req, res) => {
  res.json(SCAN_PROFILES);
});

app.post("/api/scan", (req, res) => {
  const { target, profile = "standard" } = req.body;

  if (!target) return res.status(400).json({ error: "Target is required" });
  const cleanTarget = sanitizeTarget(target.trim());
  if (!cleanTarget) return res.status(400).json({ error: "Invalid target format" });

  const prof = SCAN_PROFILES[profile] || SCAN_PROFILES.standard;
  const scanId = uuidv4();
  const xmlFile = path.join(REPORTS_DIR, `scan-${scanId}.xml`);

  // Stream response using SSE
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  send({ type: "status", message: `Starting ${prof.label} on ${cleanTarget}...` });
  send({ type: "status", message: `Nmap args: ${prof.args}` });

  const cmd = `nmap ${prof.args} -oX "${xmlFile}" ${cleanTarget} 2>&1`;
  send({ type: "status", message: "Scan in progress — this may take a few minutes..." });

  exec(cmd, { timeout: 300000 }, async (error, stdout) => {
    if (error && !fs.existsSync(xmlFile)) {
      send({ type: "error", message: `Scan failed: ${error.message}` });
      res.end();
      return;
    }

    send({ type: "status", message: "Scan complete. Parsing results..." });

    let parsed = { hosts: [], summary: "" };
    if (fs.existsSync(xmlFile)) {
      const xml = fs.readFileSync(xmlFile, "utf8");
      parsed = parseNmapXML(xml);
      fs.unlinkSync(xmlFile); // clean up XML
    }

    const pdfFile = path.join(REPORTS_DIR, `report-${scanId}.pdf`);
    try {
      send({ type: "status", message: "Generating PDF report..." });
      await generatePDF({ target: cleanTarget, profileLabel: prof.label, parsed }, pdfFile);
      const pdfUrl = `/reports/report-${scanId}.pdf`;
      send({ type: "done", scanId, parsed, pdfUrl, target: cleanTarget, profile: prof.label });
    } catch (pdfErr) {
      send({ type: "done", scanId, parsed, pdfUrl: null, target: cleanTarget, profile: prof.label, pdfError: pdfErr.message });
    }

    res.end();
  });
});

// Fallback for React
if (process.env.NODE_ENV === "production") {
  app.get("*", (req, res) => res.sendFile(path.join(__dirname, "../client/build/index.html")));
}

app.listen(PORT, () => console.log(`VulnScanner server running on port ${PORT}`));
