import { useState, useEffect, useRef } from "react";


const API = "http://127.0.0.1:8000";

/* ── Design tokens (light theme) ── */
const T = {
  bg:         "#F0F2F7",
  surface:    "#FFFFFF",
  surface2:   "#F7F8FB",
  border:     "#E4E8F0",
  border2:    "#D0D6E4",
  text:       "#0F1523",
  muted:      "#6B7489",
  hint:       "#9BA3B8",

  red:        "#E03131",
  redBg:      "#FFF0F0",
  redBorder:  "#FFBDBD",
  redLight:   "#FEE8E8",

  amber:      "#C07B00",
  amberBg:    "#FFFBEB",
  amberBorder:"#FFE08A",

  green:      "#1A7F4B",
  greenBg:    "#EDFAF3",
  greenBorder:"#A3DFBE",

  blue:       "#1B5FBF",
  blueBg:     "#EEF4FF",
  blueBorder: "#BDD1FF",

  gray:       "#4B5563",
  grayBg:     "#F3F4F6",
  grayBorder: "#D1D5DB",

  accent:     "#2563EB",
  accent2:    "#7C3AED",
  radius:     "12px",
  radiusSm:   "8px",
};

const css = {
  page: {
    minHeight: "100vh",
    background: T.bg,
    padding: "0",
    fontFamily: "'DM Sans', 'Segoe UI', sans-serif",
    color: T.text,
  },
  topBar: {
    background: T.surface,
    borderBottom: `1px solid ${T.border}`,
    padding: "0 2rem",
    display: "flex",
    alignItems: "center",
    gap: 12,
    height: 58,
  },
  logoBox: {
    width: 34, height: 34,
    background: `linear-gradient(135deg, ${T.accent}, ${T.accent2})`,
    borderRadius: 9,
    display: "flex", alignItems: "center", justifyContent: "center",
    flexShrink: 0,
  },
  main: {
    maxWidth: 820,
    margin: "0 auto",
    padding: "1.75rem 1.25rem 4rem",
  },
  card: {
    background: T.surface,
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    overflow: "hidden",
  },
  cardHead: {
    padding: "10px 16px",
    borderBottom: `1px solid ${T.border}`,
    display: "flex",
    alignItems: "center",
    gap: 8,
    fontSize: 11,
    fontWeight: 600,
    color: T.muted,
    textTransform: "uppercase",
    letterSpacing: "0.07em",
    background: T.surface2,
  },
  pill: (bg, color, border) => ({
    display: "inline-flex", alignItems: "center", gap: 5,
    fontSize: 12, fontWeight: 600,
    padding: "4px 12px",
    borderRadius: 20,
    background: bg,
    color,
    border: `1px solid ${border}`,
  }),
  statCell: (accentColor, accentBg, accentBorder) => ({
    flex: 1,
    padding: "14px 8px",
    textAlign: "center",
    borderRight: `1px solid ${T.border}`,
    background: T.surface,
  }),
  input: {
    width: "100%",
    padding: "9px 12px",
    fontSize: 13,
    borderRadius: T.radiusSm,
    border: `1px solid ${T.border2}`,
    background: T.surface,
    color: T.text,
    outline: "none",
    boxSizing: "border-box",
    fontFamily: "inherit",
  },
  btn: (disabled) => ({
    padding: "10px 26px",
    fontSize: 13,
    fontWeight: 600,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.45 : 1,
    borderRadius: T.radiusSm,
    border: "none",
    background: disabled ? T.border2 : T.accent,
    color: disabled ? T.muted : "#fff",
    letterSpacing: "0.01em",
    transition: "opacity .15s",
  }),
};

/* ── Icons (inline SVG) ── */
const Icon = ({ d, size = 14, color = "currentColor", style = {} }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
    style={{ flexShrink: 0, ...style }}>
    {Array.isArray(d) ? d.map((path, i) => <path key={i} d={path} />) : <path d={d} />}
  </svg>
);

const ShieldIcon = ({ size = 14, color = "currentColor" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

/* ── Stat grid (4 columns) ── */
function StatGrid({ malicious, suspicious, harmless, undetected }) {
  const cells = [
    { label: "Malicious",  val: malicious,  num: T.red,   bg: T.redBg,   border: T.redBorder },
    { label: "Suspicious", val: suspicious, num: T.amber, bg: T.amberBg, border: T.amberBorder },
    { label: "Harmless",   val: harmless,   num: T.green, bg: T.greenBg, border: T.greenBorder },
    { label: "Undetected", val: undetected, num: T.gray,  bg: T.grayBg,  border: T.grayBorder },
  ];
  return (
    <div style={{ display: "flex" }}>
      {cells.map(({ label, val, num, bg, border }, i) => (
        <div key={label} style={{
          flex: 1, padding: "14px 8px", textAlign: "center",
          borderRight: i < 3 ? `1px solid ${T.border}` : "none",
          background: T.surface,
        }}>
          <div style={{
            width: 30, height: 30, borderRadius: 8,
            background: bg, border: `1px solid ${border}`,
            margin: "0 auto 7px",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: num }}>{val}</span>
          </div>
          <div style={{ fontSize: 11, color: T.muted, fontWeight: 500 }}>{label}</div>
        </div>
      ))}
    </div>
  );
}

/* ── Summary strip ── */
function SummaryStrip({ malicious, total = 91, cached }) {
  const clean = malicious === 0;
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 8,
      padding: "8px 16px",
      background: clean ? T.greenBg : T.redBg,
      borderTop: `1px solid ${clean ? T.greenBorder : T.redBorder}`,
      fontSize: 12,
    }}>
      <ShieldIcon size={13} color={clean ? T.green : T.red} />
      <span style={{ fontWeight: 600, color: clean ? T.green : T.red, fontFamily: "monospace" }}>
        {malicious} threat{malicious !== 1 ? "s" : ""}
      </span>
      <span style={{ color: clean ? T.green : T.red, opacity: 0.7 }}>
        detected across {total} engines{cached ? " · cached" : ""}
      </span>
    </div>
  );
}

/* ── Gauge bar ── */
function GaugeBar({ score }) {
  const isHigh = score > 50;
  const barColor = score > 80 ? T.red : score > 50 ? T.amber : T.green;
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: T.muted, marginBottom: 5 }}>
        <span>Safe</span><span>Phishing</span>
      </div>
      <div style={{ background: T.grayBg, borderRadius: 6, height: 8, overflow: "hidden", border: `1px solid ${T.border}` }}>
        <div style={{ width: `${score}%`, height: "100%", background: barColor, borderRadius: 6, transition: "width .6s ease" }} />
      </div>
      <div style={{ textAlign: "right", fontSize: 12, marginTop: 3, color: T.muted }}>
        Phishing score: <strong style={{ color: T.text }}>{score}%</strong>
      </div>
    </div>
  );
}

/* ── Donut SVG ── */
function DonutChart({ pct, color }) {
  const r = 36, cx = 44, cy = 44;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  return (
    <svg width={88} height={88} viewBox="0 0 88 88">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={T.grayBg} strokeWidth={9} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={9}
        strokeDasharray={`${dash} ${circ}`} strokeDashoffset={circ / 4}
        strokeLinecap="round" style={{ transition: "stroke-dasharray .8s ease" }} />
      <text x={cx} y={cy - 5} textAnchor="middle" fontSize={15} fontWeight={700} fill={color}>{pct}%</text>
      <text x={cx} y={cy + 11} textAnchor="middle" fontSize={9} fill={T.muted}>phishing</text>
    </svg>
  );
}

/* ── Verdict card ── */
function VerdictCard({ result }) {
  const isPhishing = result.is_phishing;
  const score = result.phishing_score;
  const barColor = score > 80 ? T.red : score > 50 ? T.amber : T.green;
  const impersonation = result.impersonation_detected;

  const impersonationMsg = impersonation === "high"
    ? "Display name impersonates a known brand. The sender's email address is from a consumer provider — anyone can create such an account."
    : impersonation === "medium"
    ? "Subject line references a known brand, but the sender is using a personal consumer email account. Official services send from their own domain, not Gmail, Yahoo, etc."
    : null;

  return (
    <div style={{ ...css.card, marginBottom: 12 }}>
      <div style={css.cardHead}>
        <ShieldIcon size={13} color={T.muted} />
        Overall result
        <span style={{ ...css.pill(isPhishing ? T.redBg : T.greenBg, isPhishing ? T.red : T.green, isPhishing ? T.redBorder : T.greenBorder), marginLeft: "auto" }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
          {isPhishing ? "Phishing detected" : "Legitimate email"}
        </span>
      </div>
      {impersonationMsg && (
        <div style={{ margin: "0 1.5rem", marginBottom: "1rem", padding: "10px 14px", borderRadius: T.radiusSm, background: "#2d1a1a", border: `1px solid ${T.redBorder}`, display: "flex", gap: 10, alignItems: "flex-start" }}>
          <span style={{ color: T.red, fontSize: 14, lineHeight: 1, marginTop: 1 }}>⚠</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: T.red, marginBottom: 3 }}>
              {impersonation === "high" ? "Brand impersonation detected" : "Possible brand impersonation"}
            </div>
            <div style={{ fontSize: 12, color: "#e8a0a0", lineHeight: 1.5 }}>{impersonationMsg}</div>
          </div>
        </div>
      )}
      <div style={{ padding: "1.25rem 1.5rem", display: "flex", alignItems: "center", gap: "1.75rem", flexWrap: "wrap" }}>
        <DonutChart pct={score} color={barColor} />
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: T.muted, marginBottom: 5 }}>
              <span>Phishing probability</span>
              <span style={{ fontWeight: 700, color: T.red, fontFamily: "monospace" }}>{score}%</span>
            </div>
            <div style={{ background: T.grayBg, borderRadius: 6, height: 7, overflow: "hidden", border: `1px solid ${T.border}` }}>
              <div style={{ width: `${score}%`, height: "100%", background: T.red, borderRadius: 6 }} />
            </div>
          </div>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: T.muted, marginBottom: 5 }}>
              <span>Safe probability</span>
              <span style={{ fontWeight: 700, color: T.green, fontFamily: "monospace" }}>{result.safe_score}%</span>
            </div>
            <div style={{ background: T.grayBg, borderRadius: 6, height: 7, overflow: "hidden", border: `1px solid ${T.border}` }}>
              <div style={{ width: `${result.safe_score}%`, height: "100%", background: T.green, borderRadius: 6 }} />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 14 }}>
            {[["Confidence", `${result.confidence}%`], ["Safe score", `${result.safe_score}%`]].map(([l, v]) => (
              <div key={l} style={{ background: T.surface2, border: `1px solid ${T.border}`, borderRadius: T.radiusSm, padding: "8px 12px" }}>
                <div style={{ fontSize: 11, color: T.muted, marginBottom: 2 }}>{l}</div>
                <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>{v}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Raw model output card ── */
function RawModelCard({ result }) {
  const score = result.raw_phishing_score;
  if (score === undefined) return null;
  const safeScore = result.raw_safe_score;
  const isPhishing = result.raw_is_phishing;

  return (
    <div style={{ ...css.card, marginBottom: 12 }}>
      <div style={css.cardHead}>
        <ShieldIcon size={13} color={T.muted} />
        AI model raw output
        <span style={{ ...css.pill(isPhishing ? T.redBg : T.greenBg, isPhishing ? T.red : T.green, isPhishing ? T.redBorder : T.greenBorder), marginLeft: "auto" }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
          {isPhishing ? "Phishing detected" : "Legitimate email"}
        </span>
      </div>
      <div style={{ padding: "1.25rem 1.5rem", display: "flex", alignItems: "center", gap: "1.75rem", flexWrap: "wrap" }}>
        <DonutChart pct={score} />
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: T.muted, marginBottom: 5 }}>
              <span>Phishing probability</span>
              <span style={{ fontWeight: 700, color: T.red, fontFamily: "monospace" }}>{score}%</span>
            </div>
            <div style={{ background: T.grayBg, borderRadius: 6, height: 7, overflow: "hidden", border: `1px solid ${T.border}` }}>
              <div style={{ width: `${score}%`, height: "100%", background: T.red, borderRadius: 6 }} />
            </div>
          </div>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: T.muted, marginBottom: 5 }}>
              <span>Safe probability</span>
              <span style={{ fontWeight: 700, color: T.green, fontFamily: "monospace" }}>{safeScore}%</span>
            </div>
            <div style={{ background: T.grayBg, borderRadius: 6, height: 7, overflow: "hidden", border: `1px solid ${T.border}` }}>
              <div style={{ width: `${safeScore}%`, height: "100%", background: T.green, borderRadius: 6 }} />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 14 }}>
            {[["Confidence", `${result.raw_confidence}%`], ["Safe score", `${safeScore}%`]].map(([l, v]) => (
              <div key={l} style={{ background: T.surface2, border: `1px solid ${T.border}`, borderRadius: T.radiusSm, padding: "8px 12px" }}>
                <div style={{ fontSize: 11, color: T.muted, marginBottom: 2 }}>{l}</div>
                <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>{v}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Email context card ── */
function EmailContextCard({ subject, sender, displayName, topic }) {
  const fields = [
    ["Sender", sender, true],
    ["Display name", displayName || "—", false],
    ["Subject", subject || "(No subject)", false],
    ["Topic", topic || "—", false],
  ];
  return (
    <div style={{ ...css.card, marginBottom: 12 }}>
      <div style={css.cardHead}>
        <Icon d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z M22 6l-10 7L2 6" size={13} color={T.muted} />
        Email context
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr" }}>
        {fields.map(([label, val, mono], i) => (
          <div key={label} style={{
            padding: "13px 16px",
            borderRight: i % 2 === 0 ? `1px solid ${T.border}` : "none",
            borderBottom: i < fields.length - 2 ? `1px solid ${T.border}` : "none",
          }}>
            <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.07em", color: T.hint, marginBottom: 4, fontWeight: 600 }}>{label}</div>
            <div style={{ fontSize: 13, color: T.text, wordBreak: "break-all", lineHeight: 1.4, fontFamily: mono ? "monospace" : "inherit" }}>{val}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Sender reputation (domain + IP) ── */
function SenderReputationSection({ domainResult, ipResult }) {
  if (!domainResult && !ipResult) return null;
  const items = [domainResult, ipResult].filter(Boolean);
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: T.text, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 }}>
        Sender security scans · VirusTotal
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {items.map((vt, i) => {
          const label = vt.domain ? "Domain Scan" : "IP Address Scan";
          const value = vt.domain || vt.ip;
          const isMal = vt.malicious > 0;
          const theme = isMal
            ? { bg: T.surface, border: T.redBorder, iconBg: T.redBg, iconColor: T.red, title: T.text, badgeBg: T.redBg, badgeText: T.red }
            : { bg: T.surface, border: T.border, iconBg: T.surface2, iconColor: T.muted, title: T.text, badgeBg: T.surface2, badgeText: T.muted };

          const totalEngines = (vt.malicious || 0) + (vt.suspicious || 0) + (vt.harmless || 0) + (vt.undetected || 0);

          return (
            <div key={i} style={{ background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: T.radius, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "12px 16px" }}>
                <div style={{ width: 30, height: 30, borderRadius: 8, background: theme.iconBg, border: `1px solid ${T.border}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  {vt.domain
                    ? <Icon d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z M2 12h20" size={14} color={theme.iconColor} />
                    : <Icon d={["M2 2h20v8H2zM2 14h20v8H2z", "M6 6h.01M6 18h.01"]} size={14} color={theme.iconColor} />
                  }
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 10, color: T.muted, textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 600, marginBottom: 2 }}>{label}</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: theme.title, fontFamily: "monospace" }}>{value}</div>
                </div>
                <span style={{ fontSize: 10, background: theme.badgeBg, color: theme.badgeText, border: `1px solid ${T.border}`, borderRadius: 6, padding: "3px 10px", fontWeight: 600 }}>VirusTotal</span>
              </div>
              <div style={{ display: "flex", borderTop: `1px solid ${T.border}` }}>
                {[
                  { label: "Malicious",  val: vt.malicious,  num: T.red,   bg: T.surface },
                  { label: "Suspicious", val: vt.suspicious, num: T.amber, bg: T.surface },
                  { label: "Harmless",   val: vt.harmless,   num: T.green, bg: T.surface },
                  { label: "Undetected", val: vt.undetected, num: T.gray,  bg: T.surface },
                ].map(({ label: sl, val, num, bg }, ci) => (
                  <div key={sl} style={{ flex: 1, padding: "11px 6px", textAlign: "center", background: bg, borderRight: ci < 3 ? `1px solid ${T.border}` : "none" }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: num, fontFamily: "monospace" }}>{val}</div>
                    <div style={{ fontSize: 10, color: T.muted, marginTop: 2 }}>{sl}</div>
                  </div>
                ))}
              </div>
              <SummaryStrip malicious={vt.malicious} total={totalEngines} cached={vt.cached} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── URL VirusTotal section ── */
function UrlVtSection({ vt_results }) {
  const [expanded, setExpanded] = useState(false);

  if (!vt_results || vt_results.length === 0) return null;

  let maliciousCount = 0;
  let safeCount = 0;
  let failedCount = 0;

  vt_results.forEach(vt => {
    if (vt.error) {
      failedCount++;
    } else if (vt.malicious > 0) {
      maliciousCount++;
    } else {
      safeCount++;
    }
  });

  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: T.text, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 }}>
        URL security scans · VirusTotal
      </div>

      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          background: T.surface,
          border: `1px solid ${expanded ? T.accent : T.border}`,
          borderRadius: T.radius,
          padding: "12px 16px",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: expanded ? 12 : 0,
          boxShadow: expanded ? `0 0 0 3px ${T.blueBg}` : "none",
          transition: "all .15s",
        }}
      >
        <div style={{ display: "flex", gap: 10 }}>
          {maliciousCount > 0 && (
             <span style={css.pill(T.redBg, T.red, T.redBorder)}>
               {maliciousCount} Phishing
             </span>
          )}
          {safeCount > 0 && (
             <span style={css.pill(T.greenBg, T.green, T.greenBorder)}>
               {safeCount} Safe
             </span>
          )}
          {failedCount > 0 && (
             <span style={css.pill(T.grayBg, T.text, T.grayBorder)}>
               {failedCount} Failed
             </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, color: T.muted, fontSize: 12 }}>
          <span style={{ fontWeight: 600 }}>{vt_results.length} URLs</span>
          <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" style={{ transform: expanded ? "rotate(180deg)" : "rotate(0deg)", transition: "transform .2s" }}>
            <path d="M6 9l6 6 6-6" />
          </svg>
        </div>
      </div>

      {expanded && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {vt_results.map((vt, i) => {
            if (vt.error) {
              return (
                <div key={i} style={{ ...css.card, padding: "12px 16px" }}>
                  <div style={{ fontSize: 12, color: T.text, marginBottom: 4, fontFamily: "monospace", wordBreak: "break-all" }}>{vt.url}</div>
                  <div style={{ fontSize: 12, color: T.red }}>{vt.error}</div>
                </div>
              );
            }
            const isMal = vt.malicious > 0;
            const theme = isMal
              ? { bg: T.surface, border: T.redBorder, iconBg: T.redBg, iconColor: T.red, title: T.text, badgeBg: T.redBg, badgeText: T.red }
              : { bg: T.surface, border: T.border, iconBg: T.surface2, iconColor: T.muted, title: T.text, badgeBg: T.surface2, badgeText: T.muted };

            const totalEngines = (vt.malicious || 0) + (vt.suspicious || 0) + (vt.harmless || 0) + (vt.undetected || 0);

            return (
              <div key={i} style={{ background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: T.radius, overflow: "hidden" }}>
                <div style={{ padding: "12px 16px", display: "flex", alignItems: "flex-start", gap: 10 }}>
                  <div style={{ width: 30, height: 30, borderRadius: 8, background: theme.iconBg, border: `1px solid ${T.border}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 2 }}>
                    <Icon d={["M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71", "M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"]} size={14} color={theme.iconColor} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                      <span style={{ fontSize: 10, color: T.muted, textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 600 }}>URL Scan {i + 1}</span>
                      {vt.cached && <span style={{ fontSize: 10, background: T.surface2, color: T.muted, border: `1px solid ${T.border}`, borderRadius: 5, padding: "2px 7px" }}>Cached</span>}
                      <span style={{ fontSize: 10, background: theme.badgeBg, color: theme.badgeText, border: `1px solid ${T.border}`, borderRadius: 5, padding: "2px 8px", fontWeight: 600, marginLeft: "auto" }}>VirusTotal</span>
                    </div>
                    <div style={{ fontSize: 11, fontFamily: "monospace", color: theme.title, wordBreak: "break-all", lineHeight: 1.6, background: T.surface2, border: `1px solid ${T.border}`, borderRadius: 7, padding: "7px 10px" }}>
                      {vt.url}
                    </div>
                  </div>
                </div>
                <div style={{ display: "flex", borderTop: `1px solid ${T.border}` }}>
                  {[
                    { label: "Malicious",  val: vt.malicious,  num: T.red,   bg: T.surface },
                    { label: "Suspicious", val: vt.suspicious, num: T.amber, bg: T.surface },
                    { label: "Harmless",   val: vt.harmless,   num: T.green, bg: T.surface },
                    { label: "Undetected", val: vt.undetected, num: T.gray,  bg: T.surface },
                  ].map(({ label: sl, val, num, bg }, ci) => (
                    <div key={sl} style={{ flex: 1, padding: "11px 6px", textAlign: "center", background: bg, borderRight: ci < 3 ? `1px solid ${T.border}` : "none" }}>
                      <div style={{ fontSize: 20, fontWeight: 700, color: num, fontFamily: "monospace" }}>{val}</div>
                      <div style={{ fontSize: 10, color: T.muted, marginTop: 2 }}>{sl}</div>
                    </div>
                  ))}
                </div>
                <SummaryStrip malicious={vt.malicious} total={totalEngines} cached={vt.cached} />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ── Email topic card (inbox list item) ── */
function EmailTopicCard({ email, index, selected, onClick }) {
  const isPhishing = email.prediction.is_phishing;
  const score = email.prediction.phishing_score;
  const barColor = score > 80 ? T.red : score > 50 ? T.amber : T.green;

  return (
    <div
      onClick={onClick}
      style={{
        background: T.surface,
        border: `1.5px solid ${selected ? T.accent : isPhishing ? T.redBorder : T.border}`,
        borderRadius: T.radius,
        padding: "14px 16px",
        cursor: "pointer",
        transition: "border-color .15s, box-shadow .15s",
        boxShadow: selected ? `0 0 0 3px ${T.blueBg}` : "none",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Left accent bar */}
      <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 3, background: isPhishing ? T.red : T.green, borderRadius: "12px 0 0 12px" }} />

      <div style={{ paddingLeft: 8 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, marginBottom: 6 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 600, fontSize: 14, color: T.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {email.subject || "(No Subject)"}
            </div>
            <div style={{ fontSize: 12, color: T.muted, marginTop: 2, fontFamily: "monospace", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {email.sender}
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
            <span style={css.pill(
              isPhishing ? T.redBg : T.greenBg,
              isPhishing ? T.red : T.green,
              isPhishing ? T.redBorder : T.greenBorder
            )}>
              <span style={{ width: 5, height: 5, borderRadius: "50%", background: "currentColor" }} />
              {isPhishing ? "Phishing" : "Safe"}
            </span>
            <span style={{ fontSize: 11, color: T.muted, fontFamily: "monospace" }}>
              {email.prediction.confidence}% confidence
            </span>
          </div>
        </div>

        {/* Mini score bar */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
          <div style={{ flex: 1, background: T.grayBg, borderRadius: 4, height: 4, overflow: "hidden", border: `1px solid ${T.border}` }}>
            <div style={{ width: `${score}%`, height: "100%", background: barColor, borderRadius: 4 }} />
          </div>
          <span style={{ fontSize: 11, color: barColor, fontWeight: 700, fontFamily: "monospace", minWidth: 38, textAlign: "right" }}>
            {score}%
          </span>
          <span style={{ fontSize: 11, color: T.hint }}>phishing</span>
        </div>
      </div>

      {/* Expand arrow */}
      <div style={{
        position: "absolute", right: 14, bottom: 14,
        width: 22, height: 22, borderRadius: "50%",
        background: selected ? T.accent : T.surface2,
        border: `1px solid ${selected ? T.accent : T.border}`,
        display: "flex", alignItems: "center", justifyContent: "center",
        transition: "all .15s",
      }}>
        <svg width={10} height={10} viewBox="0 0 24 24" fill="none" stroke={selected ? "#fff" : T.muted} strokeWidth={2.5} strokeLinecap="round">
          <path d={selected ? "M18 15l-6-6-6 6" : "M6 9l6 6 6-6"} />
        </svg>
      </div>
    </div>
  );
}

/* ── Full detail panel (shown when card is selected) ── */
function EmailDetailPanel({ email }) {
  return (
    <div style={{ marginTop: 10, marginBottom: 4, paddingLeft: 4 }}>
      {/* section label */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <div style={{ flex: 1, height: 1, background: T.border }} />
        <span style={{ fontSize: 11, color: T.hint, textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 600 }}>Scan details</span>
        <div style={{ flex: 1, height: 1, background: T.border }} />
      </div>

      <EmailContextCard
        subject={email.subject}
        sender={email.sender}
        displayName={email.display_name}
        topic={email.topic}
      />

      <VerdictCard result={email.prediction} />
      <RawModelCard result={email.prediction} />

      <SenderReputationSection
        domainResult={email.sender_domain_result}
        ipResult={email.sender_ip_result}
      />

      <UrlVtSection vt_results={email.virustotal} />
    </div>
  );
}

/* ── Inbox result list ── */
function InboxResult({ data }) {
  const [selected, setSelected] = useState(null);

  return (
    <div style={{ marginTop: "1.5rem" }}>
      {/* Summary strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: "1.25rem" }}>
        {[
          ["Total scanned", data.summary.total_scanned, T.blue,  T.blueBg,  T.blueBorder],
          ["Phishing found", data.summary.phishing_found, T.red,  T.redBg,   T.redBorder],
          ["Legitimate",   data.summary.legitimate,    T.green, T.greenBg, T.greenBorder],
        ].map(([label, val, num, bg, border]) => (
          <div key={label} style={{ background: bg, border: `1px solid ${border}`, borderRadius: T.radius, padding: "14px 16px", textAlign: "center" }}>
            <div style={{ fontSize: 11, color: num, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: 4, opacity: 0.8 }}>{label}</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: num, fontFamily: "monospace" }}>{val}</div>
          </div>
        ))}
      </div>

      {/* Email cards */}
      <div style={{ fontSize: 11, fontWeight: 600, color: T.muted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 10 }}>
        {data.emails.length} email{data.emails.length !== 1 ? "s" : ""} scanned — click to view details
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {data.emails.map((email, i) => (
          <div key={i}>
            <EmailTopicCard
              email={email}
              index={i}
              selected={selected === i}
              onClick={() => setSelected(selected === i ? null : i)}
            />
            {selected === i && <EmailDetailPanel email={email} />}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Section divider ── */
function Divider({ label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "1.5rem 0 1rem" }}>
      <div style={{ flex: 1, height: 1, background: T.border }} />
      <span style={{ fontSize: 10, color: T.hint, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>{label}</span>
      <div style={{ flex: 1, height: 1, background: T.border }} />
    </div>
  );
}

/* ══════════════════════════════════════
   MAIN APP
══════════════════════════════════════ */
export default function App() {
  const [tab, setTab] = useState("scan");
  const [emailText, setEmailText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [imap, setImap] = useState({ host: "imap.gmail.com", port: 993, username: "asusn9546@gmail.com", password: "nbqjfbzqzbxeuchi", limit:1 });
  const [inboxResult, setInboxResult] = useState(null);
  const [autoResults, setAutoResults] = useState([]);
  const [loadingAuto, setLoadingAuto] = useState(false);
  const [countdown, setCountdown] = useState(60);
  const intervalRef = useRef(null);
  const countdownRef = useRef(null);

  useEffect(() => {
    if (tab === "results") {
      fetchAutoScanResults();
      setCountdown(60);

      countdownRef.current = setInterval(() => {
        setCountdown(prev => (prev <= 1 ? 60 : prev - 1));
      }, 1000);

      intervalRef.current = setInterval(() => {
        fetchAutoScanResults();
        setCountdown(60);
      }, 60000);
    } else {
      clearInterval(intervalRef.current);
      clearInterval(countdownRef.current);
    }

    return () => {
      clearInterval(intervalRef.current);
      clearInterval(countdownRef.current);
    };
  }, [tab]);

  async function handleScan() {
    if (!emailText.trim()) return;
    setLoading(true); setError(""); setResult(null);
    try {
      const res = await fetch(`${API}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: emailText }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error(data?.detail || `Server error (${res.status})`);
      setResult(data);
    } catch (e) {
      setError(e.name === "TypeError" && e.message.includes("fetch")
        ? "Cannot connect to backend. Make sure the server is running on port 8000."
        : e.message);
    } finally { setLoading(false); }
  }

  async function handleInboxScan() {
    setLoading(true); setError(""); setInboxResult(null);
    try {
      const res = await fetch(`${API}/scan-inbox`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(imap),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error(data?.detail || `Server error (${res.status})`);
      setInboxResult(data);
    } catch (e) {
      setError(e.name === "TypeError" && e.message.includes("fetch")
        ? "Cannot connect to backend. Make sure the server is running on port 8000."
        : e.message);
    } finally { setLoading(false); }
  }

  async function fetchAutoScanResults() {
    setLoadingAuto(true);
    try {
      const res = await fetch(`${API}/auto-scan-results`);
      const data = await res.json();
      setAutoResults(data.emails || []);
    } catch (e) {
      console.error(e);
      alert("Failed to load auto scan results");
    } finally {
      setLoadingAuto(false);
    }
  }

  return (
    <div style={css.page}>
      {/* Top bar */}
      <div style={css.topBar}>
        <div style={css.logoBox}>
          <ShieldIcon size={17} color="#fff" />
        </div>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: T.text, letterSpacing: "-.01em" }}>Phishing Detector</div>
          <div style={{ fontSize: 11, color: T.muted }}>AI-powered email threat detection</div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 4 }}>
          {[
            { id: "scan", label: "Scan Email" },
            { id: "inbox", label: "Auto Scan Inbox" },
            { id: "results", label: "Auto Scan Results" },
          ].map(t => (
            <button key={t.id} onClick={() => {
              setTab(t.id);
              setResult(null);
              setInboxResult(null);
              setError("");
            }}
              style={{
                padding: "6px 16px", fontSize: 13, fontWeight: tab === t.id ? 600 : 400,
                cursor: "pointer", border: "none", borderRadius: T.radiusSm,
                background: tab === t.id ? T.blueBg : "transparent",
                color: tab === t.id ? T.accent : T.muted,
                transition: "all .15s",
              }}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div style={css.main}>

        {/* ── SCAN EMAIL TAB ── */}
        {tab === "scan" && (
          <div>
            {/* Input card */}
            <div style={{ ...css.card, marginBottom: 12 }}>
              <div style={css.cardHead}>
                <Icon d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z M22 6l-10 7L2 6" size={13} color={T.muted} />
                Paste email content
              </div>
              <div style={{ padding: "1rem 1.25rem" }}>
                <textarea
                  value={emailText}
                  onChange={e => setEmailText(e.target.value)}
                  placeholder="Paste the full email — subject line, sender info, and body text..."
                  rows={7}
                  style={{ ...css.input, resize: "vertical", lineHeight: 1.6 }}
                />
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 10 }}>
                  <span style={{ fontSize: 12, color: T.hint }}>
                    {emailText.trim() ? `${emailText.trim().length} characters` : "Supports any email format"}
                  </span>
                  <button onClick={handleScan} disabled={loading || !emailText.trim()}
                    style={css.btn(loading || !emailText.trim())}>
                    {loading ? "Scanning…" : "Scan Email"}
                  </button>
                </div>
              </div>
            </div>

            {result && (
              <>
                <Divider label="Scan results" />
                <EmailContextCard
                  subject={result.subject}
                  sender={result.sender}
                  displayName={result.display_name}
                  topic={result.topic}
                />
                <VerdictCard result={result} />
                <SenderReputationSection
                  domainResult={result.sender_domain_result}
                  ipResult={result.sender_ip_result}
                />
                <UrlVtSection vt_results={result.virustotal} />
              </>
            )}
          </div>
        )}

        {/* ── AUTO SCAN INBOX TAB ── */}
        {tab === "inbox" && (
          <div>
            {/* IMAP input card */}
            <div style={{ ...css.card, marginBottom: 12 }}>
              <div style={css.cardHead}>
                <Icon d={["M2 2h20v8H2z", "M2 14h20v8H2z", "M6 6h.01M6 18h.01"]} size={13} color={T.muted} />
                IMAP connection
              </div>
              <div style={{ padding: "1rem 1.25rem" }}>
                <p style={{ fontSize: 13, color: T.muted, margin: "0 0 14px" }}>
                  Connect your inbox to automatically scan recent emails for phishing threats.
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
                  {[
                    { key: "host",     label: "IMAP host",     placeholder: "imap.gmail.com" },
                    { key: "port",     label: "Port",          placeholder: "993", type: "number" },
                    { key: "username", label: "Email address", placeholder: "you@gmail.com" },
                    { key: "password", label: "App password",  placeholder: "••••••••", type: "password" },
                  ].map(({ key, label, placeholder, type = "text" }) => (
                    <div key={key}>
                      <label style={{ fontSize: 11, color: T.muted, fontWeight: 600, display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</label>
                      <input type={type} value={imap[key]}
                        onChange={e => setImap(p => ({ ...p, [key]: e.target.value }))}
                        placeholder={placeholder}
                        style={css.input} />
                    </div>
                  ))}
                </div>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ fontSize: 11, color: T.muted, fontWeight: 600, display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                    Emails to scan: <span style={{ color: T.accent, fontFamily: "monospace" }}>{imap.limit}</span>
                  </label>
                  <input type="range" min="1" max="50" step="1" value={imap.limit}
                    onChange={e => setImap(p => ({ ...p, limit: Number(e.target.value) }))}
                    style={{ width: "100%", accentColor: T.accent }} />
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: T.hint, marginTop: 2 }}>
                    <span>1</span><span>50</span>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <p style={{ fontSize: 12, color: T.hint, margin: 0 }}>
                    For Gmail, use an{" "}
                    <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noreferrer"
                      style={{ color: T.accent, textDecoration: "none" }}>App Password</a>
                    , not your regular password.
                  </p>
                  <button onClick={handleInboxScan} disabled={loading || !imap.username || !imap.password}
                    style={css.btn(loading || !imap.username || !imap.password)}>
                    {loading ? "Scanning…" : "Scan Inbox"}
                  </button>
                </div>
              </div>
            </div>

            {inboxResult && <InboxResult data={inboxResult} />}
          </div>
        )}

        {/* ── AUTO SCAN RESULTS TAB ── */}
        {tab === "results" && (
          <div>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 16,
            }}>
              <div>
                <div style={{ fontSize: 20, fontWeight: 700, color: T.text }}>
                  Auto Scan Results
                </div>
                <div style={{ fontSize: 13, color: T.muted, marginTop: 4 }}>
                  Emails automatically scanned from inbox · auto-refreshes every 60s
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {/* Countdown ring */}
                <div style={{ position: "relative", width: 42, height: 42, flexShrink: 0 }}>
                  <svg width={42} height={42} viewBox="0 0 42 42" style={{ transform: "rotate(-90deg)" }}>
                    <circle cx={21} cy={21} r={17} fill="none" stroke={T.border} strokeWidth={3} />
                    <circle cx={21} cy={21} r={17} fill="none" stroke={T.accent} strokeWidth={3}
                      strokeDasharray={`${(countdown / 60) * 106.8} 106.8`}
                      strokeLinecap="round"
                      style={{ transition: "stroke-dasharray 1s linear" }}
                    />
                  </svg>
                  <div style={{
                    position: "absolute", inset: 0,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 11, fontWeight: 700, color: T.accent, fontFamily: "monospace",
                  }}>
                    {countdown}s
                  </div>
                </div>
                <button
                  onClick={() => { fetchAutoScanResults(); setCountdown(60); }}
                  style={css.btn(loadingAuto)}
                  disabled={loadingAuto}
                >
                  {loadingAuto ? "Refreshing..." : "Refresh"}
                </button>
              </div>
            </div>

            {loadingAuto ? (
              <div style={{
                padding: 30,
                textAlign: "center",
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: T.radius,
                color: T.muted,
              }}>
                Loading results...
              </div>
            ) : autoResults.length === 0 ? (
              <div style={{
                padding: 30,
                textAlign: "center",
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: T.radius,
                color: T.muted,
              }}>
                No auto scan emails found
              </div>
            ) : (
              <InboxResult
                data={{
                  summary: {
                    total_scanned: autoResults.length,
                    phishing_found: autoResults.filter(e => e.prediction?.is_phishing).length,
                    legitimate: autoResults.filter(e => !e.prediction?.is_phishing).length,
                  },
                  emails: autoResults,
                }}
              />
            )}
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{
            marginTop: "1rem", padding: "12px 16px",
            background: T.redBg, border: `1px solid ${T.redBorder}`,
            borderRadius: T.radiusSm, fontSize: 13, color: T.red,
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <Icon d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z M12 9v4M12 17h.01" size={15} color={T.red} />
            {error}
          </div>
        )}
      </div>
    </div>
  );
}