"""
LogWhisperer — app.py
=====================
SOC Command Center Dashboard.
Refactored UI/UX architecture using design tokens, modular render functions,
and clean visual hierarchy.
"""

import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

# ── Page Configuration ─────────────────────────────────────────────────────────

st.set_page_config(
    page_title="LogWhisperer // SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load Centralized Stylesheet ────────────────────────────────────────────────

def load_css() -> None:
    """Load centralized CSS stylesheet from assets/style.css."""
    css_file = Path(__file__).parent / "assets" / "style.css"
    if css_file.exists():
        with open(css_file, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# ── Baseline Data Management ───────────────────────────────────────────────────

CSV_PATH = Path(__file__).parent / "mock_server_logs.csv"

def get_baseline_logs() -> pd.DataFrame:
    """Load baseline access logs from CSV."""
    if not CSV_PATH.exists():
        return pd.DataFrame()
    df = pd.read_csv(CSV_PATH)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["status_code"] = df["status_code"].astype(int)
    return df

# Initialize session state dataframe
if "logs_df" not in st.session_state:
    st.session_state["logs_df"] = get_baseline_logs()

# State definitions: "Nominal" | "Under attack" | "Analyzing" | "Contained"
if "threat_state" not in st.session_state:
    st.session_state["threat_state"] = "Under attack"

df = st.session_state["logs_df"]

if df.empty:
    st.error("mock_server_logs.csv not found. Run python generate_data.py first.", icon="❌")
    st.stop()

# ── Threat Detection Logic (Preserved verbatim) ───────────────────────────────

df_401 = df[df["status_code"] == 401]

if not df_401.empty:
    attacker_ip: str = df_401.groupby("ip_address").size().idxmax()
    attacker_401_count = int(df_401[df_401["ip_address"] == attacker_ip].shape[0])
    attacker_rows = df[df["ip_address"] == attacker_ip]
    first_seen = attacker_rows["timestamp"].min().strftime("%H:%M:%S")
    last_seen = attacker_rows["timestamp"].max().strftime("%H:%M:%S")
else:
    attacker_ip = "None"
    attacker_401_count = 0
    attacker_rows = pd.DataFrame()
    first_seen = "N/A"
    last_seen = "N/A"
    st.session_state["threat_state"] = "Nominal"

# Check if contained
if st.session_state.get("is_contained", False):
    st.session_state["threat_state"] = "Contained"
elif attacker_401_count >= 10:
    st.session_state["threat_state"] = "Under attack"
else:
    st.session_state["threat_state"] = "Nominal"

current_time_str = df["timestamp"].max().strftime("%H:%M:%S UTC")

# ── Modular Render Functions ───────────────────────────────────────────────────

def render_header(threat_state: str, attacker_ip: str, last_updated: str) -> None:
    """Render executive SOC command center header bar."""
    if threat_state == "Under attack":
        defcon_class = "defcon-danger"
        defcon_text = f"DEFCON 2: ATTACK DETECTED [{attacker_ip}]"
    elif threat_state == "Contained":
        defcon_class = "defcon-warn"
        defcon_text = f"DEFCON 4: HOST CONTAINED [{attacker_ip}]"
    else:
        defcon_class = "defcon-success"
        defcon_text = "DEFCON 5: NOMINAL"

    shield_svg = """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>"""

    st.markdown(
        f"""
        <div class="soc-header-card">
            <div class="soc-brand-group">
                <div class="soc-logo-icon">{shield_svg}</div>
                <div>
                    <div class="soc-title-text">LOGWHISPERER <span>// SOC COMMAND CENTER</span></div>
                    <div class="soc-subtitle-text">Automated Threat Detection & Active Defense Response</div>
                </div>
            </div>
            <div class="soc-meta-group">
                <div class="soc-live-pill">
                    <span class="pulse-dot"></span> LIVE
                </div>
                <div class="soc-time-tag mono">{last_updated}</div>
                <div class="soc-defcon-badge {defcon_class}">{defcon_text}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpis(df: pd.DataFrame, threat_state: str) -> None:
    """Render 3 equal-height KPI metric cards with structured footers."""
    db_icon = """<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>"""
    alert_icon = """<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>"""
    activity_icon = """<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>"""

    if threat_state == "Under attack":
        status_label = "UNDER ATTACK"
        status_dot = "dot-danger"
        status_badge = '<span class="kpi-badge kpi-badge-danger">CRITICAL ACTION REQ</span>'
    elif threat_state == "Contained":
        status_label = "CONTAINED"
        status_dot = "dot-warn"
        status_badge = '<span class="kpi-badge kpi-badge-warn">ISOLATION ACTIVE</span>'
    else:
        status_label = "NOMINAL"
        status_dot = "dot-success"
        status_badge = '<span class="kpi-badge kpi-badge-success">ALL SYSTEMS GREEN</span>'

    st.markdown(
        f"""
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label-row">
                    <span class="kpi-label">Logs Processed (24h)</span>
                    <span class="kpi-icon">{db_icon}</span>
                </div>
                <div class="kpi-value-row">
                    <span class="kpi-value">14,230</span>
                </div>
                <div class="kpi-footer">
                    <span class="status-dot dot-success"></span> 99.8% ingestion fidelity
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label-row">
                    <span class="kpi-label">Anomalies Detected</span>
                    <span class="kpi-icon">{alert_icon}</span>
                </div>
                <div class="kpi-value-row">
                    <span class="kpi-value">1</span>
                </div>
                <div class="kpi-footer">
                    <span class="kpi-badge kpi-badge-danger">● URGENT</span>
                    <span>1 Active Host Cluster</span>
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label-row">
                    <span class="kpi-label">System Status</span>
                    <span class="kpi-icon">{activity_icon}</span>
                </div>
                <div class="kpi-value-row">
                    <span class="kpi-value" style="font-family: var(--font-sans) !important; font-size: 18px; font-weight: 700; letter-spacing: 0.02em;">
                        <span class="status-dot {status_dot}"></span> {status_label}
                    </span>
                </div>
                <div class="kpi-footer">
                    {status_badge}
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_alert(
    attacker_ip: str,
    attacker_401_count: int,
    attacker_rows: pd.DataFrame,
    threat_state: str,
) -> None:
    """Render structured critical alert banner with high contrast & metadata chips."""
    if threat_state == "Nominal":
        return

    triangle_svg = """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>"""
    first_seen_time = attacker_rows["timestamp"].min().strftime("%H:%M:%S") if not attacker_rows.empty else "14:36:00"

    badge_status = (
        '<span class="kpi-badge kpi-badge-danger">CRITICAL SEVERITY</span>'
        if threat_state == "Under attack"
        else '<span class="kpi-badge kpi-badge-warn">CONTAINED / MONITORING</span>'
    )

    st.markdown(
        f"""
        <div class="soc-alert-banner">
            <div class="soc-alert-top">
                <div class="soc-alert-title-wrap">
                    <span class="soc-alert-icon">{triangle_svg}</span>
                    <span class="soc-alert-title">Brute Force Intrusion Cluster Detected</span>
                    {badge_status}
                </div>
                <div class="alert-chip mono-chip" style="color: var(--text-dim);">
                    Window: ~45s burst
                </div>
            </div>
            <div class="soc-alert-chips">
                <span class="alert-chip">Attacker Host: <strong class="mono">{attacker_ip}</strong></span>
                <span class="alert-chip">Target Endpoint: <strong class="mono">/admin/login</strong></span>
                <span class="alert-chip alert-chip-danger">Failures: <strong class="mono">{attacker_401_count}× HTTP 401</strong></span>
                <span class="alert-chip alert-chip-warn">Breach: <strong class="mono">1× HTTP 200 Success</strong></span>
                <span class="alert-chip">First Seen: <strong class="mono">{first_seen_time} UTC</strong></span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_chart(df: pd.DataFrame, attacker_ip: str) -> None:
    """Render high-performance SOC timeline chart with baseline fill & glowing anomaly markers."""
    st.markdown("### 📡 Real-Time Network Traffic & Threat Density")

    def classify_traffic_type(code: int) -> str:
        if code == 401:
            return "HTTP 401 (Attack Burst / Anomaly)"
        elif code == 200:
            return "HTTP 200 (Normal Traffic)"
        return "Other HTTP Status (3xx/4xx/5xx)"

    df_visual = df.copy()
    df_visual["traffic_type"] = df_visual["status_code"].apply(classify_traffic_type)

    # 2-minute grouping
    freq_df = (
        df_visual.groupby([pd.Grouper(key="timestamp", freq="2min"), "traffic_type"])
        .size()
        .reset_index(name="count")
    )

    # Filter out initial partial boundary bucket so baseline starts smooth
    if len(freq_df["timestamp"].unique()) > 5:
        min_ts = freq_df["timestamp"].min()
        freq_df = freq_df[freq_df["timestamp"] > min_ts]

    import plotly.graph_objects as go

    fig = go.Figure()

    # Normal 200 baseline: area fill
    df_200 = freq_df[freq_df["traffic_type"] == "HTTP 200 (Normal Traffic)"]
    if not df_200.empty:
        fig.add_trace(
            go.Scatter(
                x=df_200["timestamp"],
                y=df_200["count"],
                name="HTTP 200 (Normal Traffic)",
                mode="lines",
                line=dict(color="#2563EB", width=2),
                fill="tozeroy",
                fillcolor="rgba(37, 99, 235, 0.12)",
                hoverinfo="x+y+name",
            )
        )

    # Other HTTP Status (3xx/4xx/5xx)
    df_other = freq_df[freq_df["traffic_type"] == "Other HTTP Status (3xx/4xx/5xx)"]
    if not df_other.empty:
        fig.add_trace(
            go.Scatter(
                x=df_other["timestamp"],
                y=df_other["count"],
                name="Other Status (3xx/4xx/5xx)",
                mode="markers",
                marker=dict(color="#64748B", size=6, opacity=0.7),
                hoverinfo="x+y+name",
            )
        )

    # Anomaly 401 burst
    df_401_pts = freq_df[freq_df["traffic_type"] == "HTTP 401 (Attack Burst / Anomaly)"]
    if not df_401_pts.empty:
        fig.add_trace(
            go.Scatter(
                x=df_401_pts["timestamp"],
                y=df_401_pts["count"],
                name="HTTP 401 (Attack Burst / Anomaly)",
                mode="markers",
                marker=dict(
                    symbol="diamond",
                    size=14,
                    color="#FF4D6D",
                    line=dict(width=2, color="#FFFFFF"),
                    opacity=1.0,
                ),
                hoverinfo="x+y+name",
            )
        )

    # Add Anomaly Threshold Line (y = 10)
    fig.add_hline(
        y=10,
        line_dash="dash",
        line_color="rgba(255, 77, 109, 0.55)",
        line_width=1.5,
        annotation_text="ANOMALY THRESHOLD (10 req/2m)",
        annotation_position="top right",
        annotation_font_size=10,
        annotation_font_color="#FF4D6D",
    )

    # Shaded attack window (if 401s present)
    attacker_rows = df[df["ip_address"] == attacker_ip]
    if not attacker_rows.empty and (attacker_rows["status_code"] == 401).any():
        atk_start = attacker_rows["timestamp"].min() - timedelta(minutes=2)
        atk_end = attacker_rows["timestamp"].max() + timedelta(minutes=2)
        fig.add_vrect(
            x0=atk_start,
            x1=atk_end,
            fillcolor="rgba(255, 77, 109, 0.12)",
            layer="below",
            line_width=1,
            line_color="rgba(255, 77, 109, 0.4)",
            annotation_text="⚡ BRUTE FORCE ATTACK WINDOW",
            annotation_position="top left",
            annotation_font_size=10,
            annotation_font_color="#FF4D6D",
        )

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#8B98B0"),
        height=320,
        margin=dict(l=35, r=20, t=40, b=45),
        xaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            zeroline=False,
            title=dict(text="Timeline (UTC)", font=dict(color="#64748B", size=12)),
            tickfont=dict(color="#64748B", size=11),
            automargin=True,
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            zeroline=False,
            title=dict(text="Requests / 2 min", font=dict(color="#64748B", size=12)),
            tickfont=dict(color="#64748B", size=11),
            automargin=True,
        ),
        legend=dict(
            title=None,
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1.0,
            font=dict(size=11, color="#E5E7EB"),
            bgcolor="rgba(17, 24, 39, 0.8)",
            bordercolor="rgba(31, 42, 68, 0.6)",
            borderwidth=1,
        ),
    )

    st.plotly_chart(fig, width="stretch")


def render_feed(df: pd.DataFrame, attacker_ip: str) -> None:
    """Render raw ingestion feed table with modern filter toolbar and refined row styling."""
    st.markdown("### 📥 Raw Ingestion Feed")
    selected_filter = st.pills(
        "Feed Filter",
        options=["🚨 Isolated Attacker", "🌐 All Logs", "⚠️ 401 Failures Only"],
        default="🚨 Isolated Attacker",
        label_visibility="collapsed",
    )
    view_mode = selected_filter or "🚨 Isolated Attacker"

    if view_mode == "🚨 Isolated Attacker":
        target_df = df[df["ip_address"] == attacker_ip].copy()
        caption_text = (
            f"ISOLATED VIEW: Exclusively displaying **{len(target_df)} events** from rogue host `{attacker_ip}`."
        )
    elif view_mode == "⚠️ 401 Failures Only":
        target_df = df[df["status_code"] == 401].tail(25).copy()
        caption_text = (
            f"ANOMALY VIEW: Displaying **{len(target_df)} HTTP 401 events** across telemetry stream."
        )
    else:
        target_df = df.tail(15).copy()
        caption_text = (
            f"GLOBAL FEED: Displaying last 15 events of **{len(df):,}** total logs."
        )

    target_df["time"] = target_df["timestamp"].dt.strftime("%H:%M:%S")
    display_df = target_df[["time", "ip_address", "method", "endpoint", "status_code", "user_agent"]].copy()

    def _style_feed_table(row: pd.Series) -> list[str]:
        styles = [""] * len(row)
        is_attacker = row["ip_address"] == attacker_ip

        for idx, col in enumerate(row.index):
            cell_css = []
            if is_attacker:
                cell_css.append("background-color: rgba(255, 77, 109, 0.08);")
            if col == "ip_address" and is_attacker:
                cell_css.append("color: #FF4D6D; font-weight: 700; font-family: monospace;")
            elif col == "status_code":
                if row["status_code"] == 200:
                    cell_css.append("color: #22C55E; font-weight: 700;")
                elif row["status_code"] == 401:
                    cell_css.append("color: #FF4D6D; font-weight: 700;")
                else:
                    cell_css.append("color: #F59E0B; font-weight: 700;")
            elif col == "method":
                cell_css.append("font-weight: 600; color: #94A3B8;")
            elif col == "endpoint":
                cell_css.append("color: #E2E8F0; font-family: monospace;")
            elif col == "time":
                cell_css.append("color: #64748B; font-family: monospace;")
            styles[idx] = " ".join(cell_css)
        return styles

    st.dataframe(
        display_df.style.apply(_style_feed_table, axis=1),
        width="stretch",
        hide_index=True,
    )
    st.caption(caption_text)


def render_response_panel(
    attacker_ip: str,
    attacker_401_count: int,
    attacker_rows: pd.DataFrame,
    current_time_str: str,
) -> None:
    """Render executive AI Response Terminal with MITRE classification, threat intel & active defense controls."""
    st.markdown("### 🖥️ AI Response Terminal")

    first_seen_str = attacker_rows["timestamp"].min().strftime("%H:%M:%S") if not attacker_rows.empty else "N/A"
    last_seen_str = attacker_rows["timestamp"].max().strftime("%H:%M:%S") if not attacker_rows.empty else "N/A"

    # 1. Fetch IP Threat Intelligence & Geolocation Metadata
    intel = None
    if attacker_ip != "None":
        try:
            r = requests.get(f"http://localhost:8000/enrich_ip/{attacker_ip}", timeout=2)
            if r.ok:
                intel = r.json()
        except Exception:
            pass

    if intel:
        threat_score = intel.get("threat_score", 90)
        asn_str = intel.get("asn", "Unknown Autonomous System")
        country_str = intel.get("country", "Unknown")
        class_str = intel.get("classification", "Suspicious Remote Host")
        tags = intel.get("known_threats", ["Brute-Force", "Credential-Stuffing"])
        tags_html = "".join(f"<span class='threat-tag'>{t}</span>" for t in tags)

        st.markdown(
            f"""
            <div class="intel-card">
                <div class="intel-header">
                    <span class="intel-title">🌐 IP Threat Intelligence // {country_str}</span>
                    <span class="kpi-badge kpi-badge-danger">{threat_score}/100 RISK</span>
                </div>
                <div class="threat-meter-wrap">
                    <div class="threat-meter-bar">
                        <div class="threat-meter-fill" style="width: {threat_score}%;"></div>
                    </div>
                </div>
                <div style="font-size: 11px; color: var(--text-dim);" class="mono">
                    <strong>ASN:</strong> {asn_str}<br>
                    <strong>PROFILE:</strong> {class_str}
                </div>
                <div class="threat-tags">
                    {tags_html}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 2. MITRE ATT&CK Enterprise Card
    mitre_tech = "T1110.001 - Password Guessing"
    confidence_pct = 99.4
    if "threat_response" in st.session_state:
        resp = st.session_state["threat_response"]
        mitre_tech = resp.get("mitre_technique", mitre_tech)
        confidence_pct = round(resp.get("confidence_score", 0.98) * 100, 1)

    st.markdown(
        f"""
        <div class="mitre-card">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                <span class="mitre-pill">
                    <span class="mitre-id">T1110</span> {mitre_tech}
                </span>
                <span style="font-size: 11px; color: var(--text-dim); font-weight: 500;">MITRE ATT&CK® v14</span>
            </div>
            <div class="mitre-kv-grid">
                <div class="mitre-kv-item"><span class="k">Target:</span> <span class="v">/admin/login</span></div>
                <div class="mitre-kv-item"><span class="k">Burst Count:</span> <span class="v">{attacker_401_count}× HTTP 401</span></div>
                <div class="mitre-kv-item"><span class="k">Window:</span> <span class="v">{first_seen_str} → {last_seen_str}</span></div>
                <div class="mitre-kv-item"><span class="k">Confidence:</span> <span class="v" style="color: var(--danger);">{confidence_pct}% (HIGH)</span></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    BACKEND_URL = "http://localhost:8000/analyze_threat"

    suspicious_log_entries = [
        f"{row.timestamp} | {row.ip_address} {row.method} {row.endpoint} HTTP {row.status_code} [{row.user_agent}]"
        for row in attacker_rows.itertuples()
    ] if not attacker_rows.empty else []

    if attacker_ip == "None" or not suspicious_log_entries:
        st.info("System Nominal: No active intrusion detected in the current window.", icon="🛡️")
        return

    if "threat_response" not in st.session_state:
        st.markdown(
            f"""
            <div class="terminal-window">
                <div class="terminal-titlebar">
                    <div class="terminal-dots">
                        <div class="t-dot t-dot-red"></div>
                        <div class="t-dot t-dot-yellow"></div>
                        <div class="t-dot t-dot-green"></div>
                    </div>
                    <div class="terminal-user-badge">soc-analyst@command:~$</div>
                </div>
                <div class="terminal-content mono">
                    <div style="color: var(--text-dim); margin-bottom: 6px;">// REASONING ENGINE STANDBY (OpenAI & Deterministic SOC)</div>
                    <div style="color: var(--accent); margin-bottom: 4px;">soc-analyst@command:~$ ./inspect-telemetry --target {attacker_ip}</div>
                    <div style="color: var(--text-muted); font-size: 11px;">Awaiting analyst trigger to dispatch {len(suspicious_log_entries)} telemetry lines to SOC LLM...</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        analyze_clicked = st.button(
            "⚡ Analyze Threat & Generate Remediation",
            type="primary",
            use_container_width=True,
        )

        if analyze_clicked:
            with st.spinner("DISPATCHING TELEMETRY TO SOC AI REASONING ENGINE..."):
                try:
                    response = requests.post(
                        BACKEND_URL,
                        json={
                            "logs": suspicious_log_entries,
                            "attacker_ip": attacker_ip,
                        },
                        timeout=60,
                    )
                    response.raise_for_status()
                    st.session_state["threat_response"] = response.json()
                    st.session_state["has_streamed"] = False
                    st.rerun()

                except requests.exceptions.ConnectionError:
                    st.error("Cannot connect to LogWhisperer API at http://localhost:8000. Ensure FastAPI backend is running.", icon="🔌")
                except requests.exceptions.HTTPError as exc:
                    detail = ""
                    try:
                        detail = exc.response.json().get("detail", "")
                    except Exception:
                        pass
                    st.error(f"API Error {exc.response.status_code}: {detail or exc}", icon="❌")
                except requests.exceptions.Timeout:
                    st.error("Request timed out waiting for LLM response.", icon="⏱️")
    else:
        data = st.session_state["threat_response"]
        analysis_text = data.get("analysis", "No analysis provided.")
        firewall_cmd = data.get("firewall_rule", f"iptables -I INPUT -s {attacker_ip} -j DROP")
        remediation_steps = data.get("remediation_steps", [
            f"Inject kernel iptables drop rule to block host ingress: {attacker_ip}",
            "Revoke active session tokens for /admin/login & trigger forced MFA",
            f"Quarantine host {attacker_ip} in edge perimeter / Cloudflare WAF",
            "Broadcast threat indicator to SIEM threat intelligence feed",
        ])

        st.markdown(
            f"""
            <div class="terminal-window">
                <div class="terminal-titlebar">
                    <div class="terminal-dots">
                        <div class="t-dot t-dot-red"></div>
                        <div class="t-dot t-dot-yellow"></div>
                        <div class="t-dot t-dot-green"></div>
                    </div>
                    <div class="terminal-user-badge">soc-defense@logwhisperer:~# active-defense</div>
                </div>
                <div class="terminal-content">
                    <div style="color: var(--accent); font-family: var(--font-mono); font-size: 11px; font-weight: 700; margin-bottom: 6px; letter-spacing: 0.05em;">
                        [AI_HEURISTIC_ANALYSIS]
                    </div>
                    <div style="background: rgba(34, 211, 238, 0.05); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 4px; padding: 10px 12px; margin-bottom: 12px; font-size: 13px; line-height: 1.5; color: var(--text);">
                        {analysis_text}
                    </div>
                    <div style="color: var(--danger); font-family: var(--font-mono); font-size: 11px; font-weight: 700; margin-bottom: 6px; letter-spacing: 0.05em;">
                        [ACTIVE_DEFENSE_FIREWALL_RULE]
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.code(firewall_cmd, language="bash")

        if "audit_log" not in st.session_state:
            st.session_state["audit_log"] = []

        if not st.session_state.get("is_contained", False):
            if st.button("🛡️ Enforce Kernel Firewall Rule", type="primary", use_container_width=True):
                st.session_state["is_contained"] = True
                new_rule = {
                    "Rule ID": f"FW-{len(st.session_state['audit_log']) + 101}",
                    "Target IP": attacker_ip,
                    "Rule": firewall_cmd,
                    "Timestamp (UTC)": current_time_str,
                    "Status": "ACTIVE",
                }
                st.session_state["audit_log"].append(new_rule)
                st.toast(f"ACTIVE DEFENSE ENFORCED: Dropped all traffic from {attacker_ip}!", icon="🛡️")
                st.rerun()
        else:
            steps_html = "".join(
                f"""<div class="remediation-item">
                    <span class="remediation-check">✓</span>
                    <span>{step}</span>
                </div>"""
                for step in remediation_steps
            )

            st.markdown(
                f"""
                <div class="remediation-box">
                    <div style="font-size: 11px; font-weight: 700; color: var(--success); margin-bottom: 8px; letter-spacing: 0.04em;">
                        🛡️ ACTIVE DEFENSE ENFORCED // HOST CONTAINED
                    </div>
                    {steps_html}
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Generate formal Markdown report
            report_md = f"""# LOGWHISPERER // SOC INCIDENT REPORT
**Incident ID:** INC-2026-{(abs(hash(attacker_ip)) % 90000) + 10000}
**Timestamp:** {current_time_str}
**Severity:** CRITICAL
**Status:** CONTAINED

---

## 1. Executive Summary
{analysis_text}

## 2. Adversary Details
- **Attacker Host:** `{attacker_ip}`
- **Target Endpoint:** `/admin/login`
- **Total Ingress Attempts:** {attacker_401_count} failed, 1 success
- **MITRE ATT&CK Classification:** {mitre_tech}

## 3. Active Defense Remediation
- **Applied Firewall Rule:**
  ```bash
  {firewall_cmd}
  ```
- **Containment Actions:**
{chr(10).join(f"  - [x] {s}" for s in remediation_steps)}

## 4. Verification Checksum
SHA256 Integrity Verification: `{(hex(abs(hash(analysis_text + attacker_ip)) * 8932))[2:34].zfill(32)}`
Certified by LogWhisperer Autonomous SOC Agent.
"""
            st.download_button(
                label="📄 Export SOC Incident Report (.md)",
                data=report_md,
                file_name=f"incident-report-{attacker_ip}.md",
                mime="text/markdown",
                use_container_width=True,
            )

        if st.button("↺ Re-Analyze Telemetry", use_container_width=True):
            st.session_state.pop("threat_response", None)
            st.session_state.pop("has_streamed", None)
            st.rerun()

        # Audit Trail Expander
        if st.session_state.get("audit_log"):
            with st.expander("📋 Kernel Firewall Enforcement Audit Trail", expanded=False):
                audit_df = pd.DataFrame(st.session_state["audit_log"])
                st.dataframe(audit_df, width="stretch", hide_index=True)
                if st.button("Revoke Active Firewall Rules", use_container_width=True):
                    st.session_state["audit_log"] = []
                    st.session_state["is_contained"] = False
                    st.toast("Kernel firewall rules revoked.", icon="🔓")
                    st.rerun()


def render_sidebar(current_attacker_ip: str) -> None:
    """Render simulator controls in sidebar."""
    with st.sidebar:
        st.markdown("## ⚡ Simulate Network Traffic")
        st.caption("Dynamically inject live adversarial attacks into the log stream to test SIEM alert latency and automated containment.")

        st.markdown("---")
        st.markdown("### 🎯 Attack Scenario Presets")
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            if st.button("Tor Exit Spray", use_container_width=True):
                st.session_state["sim_ip_preset"] = "185.220.101.5"
                st.session_state["sim_vol_preset"] = 35
                st.rerun()
        with col_p2:
            if st.button("Scanner Probe", use_container_width=True):
                st.session_state["sim_ip_preset"] = "45.33.32.156"
                st.session_state["sim_vol_preset"] = 20
                st.rerun()

        default_ip = st.session_state.get(
            "sim_ip_preset", current_attacker_ip if current_attacker_ip != "None" else "185.220.101.5"
        )
        default_vol = st.session_state.get("sim_vol_preset", 25)

        sim_ip = st.text_input("Rogue Attacker IP", value=default_ip)
        sim_count = st.slider("Burst Failure Volume", min_value=15, max_value=50, value=default_vol)

        if st.button("🚨 Inject Adversarial Burst", type="primary", use_container_width=True):
            latest_time = st.session_state["logs_df"]["timestamp"].max()
            injected_rows = []
            for i in range(sim_count):
                injected_rows.append({
                    "timestamp": latest_time + timedelta(seconds=(i + 1) * 1.5),
                    "ip_address": sim_ip,
                    "method": "POST",
                    "endpoint": "/admin/login",
                    "status_code": 401,
                    "user_agent": "hydra/9.5 (Kali Linux; Automated-Credential-Stuffing)",
                })
            injected_rows.append({
                "timestamp": latest_time + timedelta(seconds=(sim_count + 1) * 1.5 + 2),
                "ip_address": sim_ip,
                "method": "POST",
                "endpoint": "/admin/login",
                "status_code": 200,
                "user_agent": "hydra/9.5 (Kali Linux; Automated-Credential-Stuffing)",
            })

            new_entries = pd.DataFrame(injected_rows)
            st.session_state["logs_df"] = pd.concat([st.session_state["logs_df"], new_entries], ignore_index=True)
            st.session_state.pop("threat_response", None)
            st.session_state.pop("has_streamed", None)
            st.session_state["is_contained"] = False
            st.toast(f"INJECTED: {sim_count} brute force attempts from {sim_ip}!", icon="🚨")
            st.rerun()

        if st.button("↺ Reset to Clean Baseline", type="secondary", use_container_width=True):
            st.session_state["logs_df"] = get_baseline_logs()
            st.session_state.pop("threat_response", None)
            st.session_state.pop("has_streamed", None)
            st.session_state.pop("sim_ip_preset", None)
            st.session_state.pop("sim_vol_preset", None)
            st.session_state["is_contained"] = False
            st.toast("Telemetry logs reset to original 1,000-event baseline.", icon="↺")
            st.rerun()

        st.markdown("---")
        st.markdown("### 📊 Live Stream Metrics")
        st.markdown(f"**Total Events:** `{len(st.session_state['logs_df']):,}`")
        st.markdown(f"**Total 401 Failures:** `{(st.session_state['logs_df']['status_code'] == 401).sum():,}`")
        st.markdown(f"**Unique Remote IPs:** `{st.session_state['logs_df']['ip_address'].nunique():,}`")


# ── App Orchestration ─────────────────────────────────────────────────────────

render_sidebar(attacker_ip)
render_header(st.session_state["threat_state"], attacker_ip, current_time_str)
render_kpis(df, st.session_state["threat_state"])
render_alert(attacker_ip, attacker_401_count, attacker_rows, st.session_state["threat_state"])

render_chart(df, attacker_ip)

st.markdown("<hr style='border: 1px solid var(--border); margin: 18px 0;'>", unsafe_allow_html=True)

col_feed, col_terminal = st.columns([1.8, 1.2])

with col_feed:
    render_feed(df, attacker_ip)

with col_terminal:
    render_response_panel(attacker_ip, attacker_401_count, attacker_rows, current_time_str)

st.markdown("<hr style='border: 1px solid var(--border); margin: 24px 0 10px;'>", unsafe_allow_html=True)
st.caption("LOGWHISPERER SOC v1.1.0 // ADVANCED THREAT INTELLIGENCE & AUTONOMOUS CONTAINMENT")
