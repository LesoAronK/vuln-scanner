import React, { useState, useEffect, useRef } from "react";

// ─── Icons (inline SVG) ───────────────────────────────────────────────────────
const Icon = ({ d, size = 16, color = "currentColor" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);

const SEV_CONFIG = {
  critical: { color: "#f85149", bg: "#3d1e1e", label: "CRITICAL" },
  high:     { color: "#ff7b72", bg: "#2d1f1e", label: "HIGH" },
  medium:   { color: "#e3b341", bg: "#2d2416", label: "MEDIUM" },
  low:      { color: "#3fb950", bg: "#1a2d1e", label: "LOW" },
  info:     { color: "#8b949e", bg: "#1c2128", label: "INFO" },
};

// ─── Sub-components ───────────────────────────────────────────────────────────
function Badge({ sev }) {
  const c = SEV_CONFIG[sev] || SEV_CONFIG.info;
  return (
    <span style={{ background: c.bg, color: c.color, border: `1px solid ${c.color}44`, padding: "2px 8px", borderRadius: 4, fontSize: 10, fontFamily: "var(--font-mono)", fontWeight: 700, letterSpacing: 1 }}>
      {c.label}
    </span>
  );
}

function StatCard({ value, label, color = "#58a6ff" }) {
  return (
    <div style={{ background: "#161b22", border: "1px solid #21262d", borderRadius: 10, padding: "16px 20px", flex: 1, minWidth: 100 }}>
      <div style={{ fontSize: 28, fontWeight: 700, color, fontFamily: "var(--font-mono)" }}>{value}</div>
      <div style={{ fontSize: 11, color: "#8b949e", marginTop: 2, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
    </div>
  );
}

function PortRow({ p }) {
  const c = SEV_CONFIG[p.severity] || SEV_CONFIG.info;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 12px", borderBottom: "1px solid #21262d", fontSize: 12 }}>
      <span style={{ fontFamily: "var(--font-mono)", color: "#58a6ff", width: 55, flexShrink: 0 }}>{p.port}/{p.protocol}</span>
      <span style={{ color: "#e6edf3", width: 100, flexShrink: 0 }}>{p.service || "—"}</span>
      <span style={{ color: "#8b949e", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.version || "—"}</span>
      <Badge sev={p.severity} />
    </div>
  );
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false);
  const c = SEV_CONFIG[f.severity] || SEV_CONFIG.info;
  return (
    <div style={{ borderBottom: "1px solid #21262d" }}>
      <div onClick={() => setOpen(!open)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "9px 12px", cursor: "pointer", userSelect: "none" }}>
        <span style={{ color: c.color, fontSize: 12 }}>{open ? "▼" : "▶"}</span>
        <Badge sev={f.severity} />
        <span style={{ fontSize: 12, color: "#e6edf3", flex: 1 }}>{f.issue}</span>
      </div>
      {open && (
        <div style={{ padding: "8px 16px 12px 36px", fontSize: 12, color: "#8b949e", background: "#161b22", borderTop: "1px solid #21262d" }}>
          {f.detail}
        </div>
      )}
    </div>
  );
}

function HostCard({ host }) {
  const openPorts = host.ports.filter((p) => p.state === "open");
  const [tab, setTab] = useState("ports");
  const criticals = host.findings.filter((f) => f.severity === "critical").length;
  return (
    <div style={{ background: "#161b22", border: "1px solid #21262d", borderRadius: 10, overflow: "hidden", marginBottom: 16 }}>
      {/* Host header */}
      <div style={{ padding: "14px 18px", borderBottom: "1px solid #21262d", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, color: "#58a6ff", fontWeight: 700 }}>{host.ip}</div>
          {host.hostname && <div style={{ fontSize: 11, color: "#8b949e" }}>{host.hostname}</div>}
        </div>
        <span style={{ background: host.status === "up" ? "#1a2d1e" : "#2d1e1e", color: host.status === "up" ? "#3fb950" : "#f85149", border: `1px solid ${host.status === "up" ? "#3fb950" : "#f85149"}44`, padding: "2px 10px", borderRadius: 20, fontSize: 11, fontWeight: 600 }}>
          {host.status?.toUpperCase()}
        </span>
        {host.osGuess && <span style={{ fontSize: 11, color: "#8b949e", fontFamily: "var(--font-mono)" }}>🖥 {host.osGuess}</span>}
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <span style={{ fontSize: 11, color: "#58a6ff" }}>{openPorts.length} open ports</span>
          {criticals > 0 && <span style={{ fontSize: 11, color: "#f85149", fontWeight: 700 }}>{criticals} critical</span>}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #21262d" }}>
        {["ports", "findings"].map((t) => (
          <button key={t} onClick={() => setTab(t)} style={{ padding: "8px 18px", background: "none", border: "none", borderBottom: tab === t ? "2px solid #58a6ff" : "2px solid transparent", color: tab === t ? "#58a6ff" : "#8b949e", cursor: "pointer", fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>
            {t === "ports" ? `Ports (${openPorts.length})` : `Findings (${host.findings.length})`}
          </button>
        ))}
      </div>

      {tab === "ports" && (
        <div>
          {openPorts.length === 0 ? (
            <div style={{ padding: 20, color: "#8b949e", fontSize: 12, textAlign: "center" }}>No open ports detected</div>
          ) : (
            <div>
              <div style={{ display: "flex", gap: 12, padding: "6px 12px", fontSize: 10, color: "#8b949e", textTransform: "uppercase", letterSpacing: 1, borderBottom: "1px solid #21262d", background: "#1c2128" }}>
                <span style={{ width: 55 }}>Port</span>
                <span style={{ width: 100 }}>Service</span>
                <span style={{ flex: 1 }}>Version</span>
                <span>Risk</span>
              </div>
              {openPorts.map((p, i) => <PortRow key={i} p={p} />)}
            </div>
          )}
        </div>
      )}

      {tab === "findings" && (
        <div>
          {host.findings.length === 0 ? (
            <div style={{ padding: 20, color: "#3fb950", fontSize: 12, textAlign: "center" }}>✓ No security findings on this host</div>
          ) : (
            host.findings.map((f, i) => <FindingRow key={i} f={f} />)
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [profiles, setProfiles] = useState({});
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("standard");
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const logsRef = useRef(null);

  useEffect(() => {
    fetch("/api/profiles").then((r) => r.json()).then(setProfiles).catch(() => {});
  }, []);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const startScan = async () => {
    if (!target.trim() || scanning) return;
    setScanning(true);
    setLogs([]);
    setResult(null);
    setError(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), profile }),
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === "status") setLogs((l) => [...l, { ts: new Date().toLocaleTimeString(), msg: data.message }]);
            if (data.type === "error") { setError(data.message); setScanning(false); }
            if (data.type === "done") { setResult(data); setScanning(false); }
          } catch {}
        }
      }
    } catch (e) {
      setError("Connection error: " + e.message);
      setScanning(false);
    }
  };

  // Stats
  let totalOpen = 0, totalFindings = 0, totalCritical = 0;
  if (result?.parsed?.hosts) {
    result.parsed.hosts.forEach((h) => {
      totalOpen += h.ports.filter((p) => p.state === "open").length;
      totalFindings += h.findings.length;
      totalCritical += h.findings.filter((f) => f.severity === "critical").length;
    });
  }

  return (
    <div style={{ minHeight: "100vh", background: "#0d1117" }}>
      {/* Header */}
      <div style={{ borderBottom: "1px solid #21262d", padding: "14px 32px", display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 32, height: 32, background: "linear-gradient(135deg, #1f6feb, #388bfd)", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15, fontFamily: "var(--font-mono)", color: "#e6edf3" }}>VulnScanner</div>
          <div style={{ fontSize: 10, color: "#8b949e", letterSpacing: 1 }}>NETWORK VULNERABILITY ASSESSMENT</div>
        </div>
        <div style={{ marginLeft: "auto", fontSize: 11, color: "#8b949e", fontFamily: "var(--font-mono)" }}>
          Powered by Nmap
        </div>
      </div>

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "28px 24px" }}>
        {/* Disclaimer */}
        <div style={{ background: "#2d2416", border: "1px solid #e3b34144", borderRadius: 8, padding: "10px 16px", marginBottom: 24, display: "flex", gap: 10, alignItems: "flex-start" }}>
          <span style={{ color: "#e3b341", fontSize: 14 }}>⚠</span>
          <div style={{ fontSize: 12, color: "#e3b341" }}>
            <strong>Authorized use only.</strong> Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.
          </div>
        </div>

        {/* Scan form */}
        <div style={{ background: "#161b22", border: "1px solid #21262d", borderRadius: 12, padding: 24, marginBottom: 24 }}>
          <h2 style={{ fontSize: 14, fontWeight: 700, color: "#8b949e", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>Configure Scan</h2>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
            <div style={{ flex: 2, minWidth: 220 }}>
              <label style={{ fontSize: 11, color: "#8b949e", display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>Target</label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && startScan()}
                placeholder="192.168.1.1  or  scanme.nmap.org  or  10.0.0.0/24"
                disabled={scanning}
                style={{ width: "100%", background: "#0d1117", border: "1px solid #21262d", borderRadius: 8, padding: "10px 14px", color: "#e6edf3", fontSize: 13, fontFamily: "var(--font-mono)", outline: "none" }}
              />
            </div>
            <div style={{ flex: 1, minWidth: 180 }}>
              <label style={{ fontSize: 11, color: "#8b949e", display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>Scan Profile</label>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                disabled={scanning}
                style={{ width: "100%", background: "#0d1117", border: "1px solid #21262d", borderRadius: 8, padding: "10px 14px", color: "#e6edf3", fontSize: 13, outline: "none" }}
              >
                {Object.entries(profiles).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
          </div>

          {profiles[profile] && (
            <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 16, fontFamily: "var(--font-mono)" }}>
              <span style={{ color: "#58a6ff" }}>nmap</span> {profiles[profile].args} &lt;target&gt;
              <span style={{ marginLeft: 12, color: "#3fb950" }}>— {profiles[profile].desc}</span>
            </div>
          )}

          <button
            onClick={startScan}
            disabled={scanning || !target.trim()}
            style={{ background: scanning || !target.trim() ? "#1c2128" : "linear-gradient(135deg, #1f6feb, #388bfd)", color: scanning || !target.trim() ? "#8b949e" : "white", border: "none", borderRadius: 8, padding: "10px 28px", fontSize: 13, fontWeight: 600, cursor: scanning || !target.trim() ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: 8 }}>
            {scanning ? (
              <>
                <span style={{ display: "inline-block", width: 14, height: 14, border: "2px solid #58a6ff44", borderTopColor: "#58a6ff", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                Scanning...
              </>
            ) : "▶  Start Scan"}
          </button>
        </div>

        {/* Live logs */}
        {(scanning || logs.length > 0) && (
          <div style={{ background: "#161b22", border: "1px solid #21262d", borderRadius: 12, marginBottom: 24, overflow: "hidden" }}>
            <div style={{ padding: "10px 16px", borderBottom: "1px solid #21262d", fontSize: 11, color: "#8b949e", textTransform: "uppercase", letterSpacing: 1, display: "flex", alignItems: "center", gap: 8 }}>
              {scanning && <span style={{ display: "inline-block", width: 8, height: 8, background: "#3fb950", borderRadius: "50%", animation: "pulse 1s ease infinite" }} />}
              Live Output
            </div>
            <div ref={logsRef} style={{ padding: "12px 16px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#8b949e", maxHeight: 180, overflowY: "auto", lineHeight: 1.8 }}>
              {logs.map((l, i) => (
                <div key={i}><span style={{ color: "#21262d" }}>[{l.ts}]</span> <span style={{ color: "#3fb950" }}>$</span> {l.msg}</div>
              ))}
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{ background: "#3d1e1e", border: "1px solid #f8514944", borderRadius: 10, padding: "14px 18px", marginBottom: 24, color: "#f85149", fontSize: 13 }}>
            ✗ {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div>
            {/* Summary stats */}
            <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
              <StatCard value={result.parsed.hosts.length} label="Hosts Found" color="#58a6ff" />
              <StatCard value={totalOpen} label="Open Ports" color="#e3b341" />
              <StatCard value={totalFindings} label="Findings" color="#ff7b72" />
              <StatCard value={totalCritical} label="Critical" color="#f85149" />
            </div>

            {/* PDF download */}
            {result.pdfUrl && (
              <div style={{ background: "#1a2d1e", border: "1px solid #3fb95044", borderRadius: 10, padding: "14px 18px", marginBottom: 20, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
                <div>
                  <div style={{ color: "#3fb950", fontWeight: 700, fontSize: 13 }}>✓ Scan Complete — Report Ready</div>
                  <div style={{ color: "#8b949e", fontSize: 11, marginTop: 2 }}>Target: {result.target}  |  Profile: {result.profile}</div>
                </div>
                <a href={result.pdfUrl} download={`vuln-report-${result.target}.pdf`} style={{ background: "#3fb950", color: "#0d1117", padding: "8px 20px", borderRadius: 8, textDecoration: "none", fontWeight: 700, fontSize: 13 }}>
                  ↓ Download PDF Report
                </a>
              </div>
            )}

            {/* Host cards */}
            {result.parsed.hosts.length === 0 ? (
              <div style={{ background: "#161b22", border: "1px solid #21262d", borderRadius: 10, padding: 32, textAlign: "center", color: "#8b949e" }}>
                No hosts found. The target may be offline or blocking probes.
              </div>
            ) : (
              result.parsed.hosts.map((h, i) => <HostCard key={i} host={h} />)
            )}
          </div>
        )}
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        input:focus, select:focus { border-color: #388bfd !important; }
        input::placeholder { color: #484f58; }
      `}</style>
    </div>
  );
}
