import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="Blue Team SOC Dashboard", page_icon="🛡️", layout="wide")

# ---- Load CSS ----
with open("assets/styles.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# =================== Helpers ===================
EVENT_TYPES = ["failed_login", "successful_login", "port_scan", "suspicious_login"]

def _pick_ip(rng, offenders, public_pool, local_pool):
    cat = rng.choice(["offender", "public", "local"], p=[0.25, 0.35, 0.40])
    if cat == "offender":
        return rng.choice(offenders), "High"
    elif cat == "public":
        return rng.choice(public_pool), "Medium"
    else:
        return rng.choice(local_pool), "Low"

def generate_demo_data(minutes: int = 180, step_seconds: int = 30, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    now = pd.Timestamp.utcnow().tz_localize(None)
    start = now - pd.Timedelta(minutes=minutes)
    timestamps = pd.date_range(start, now, freq=f"{step_seconds}s")

    local_pool = [f"192.168.1.{i}" for i in range(10, 60, 2)]
    public_pool = [f"203.0.113.{i}" for i in range(10, 50, 5)] + \
                  [f"198.51.100.{i}" for i in range(20, 60, 5)]
    offenders = ["45.83.12.7", "77.21.56.99", "91.200.12.44", "185.220.100.1"]

    users = ["alice", "bob", "charlie", "diana", "eve", "frank"]
    servers = ["10.0.0.10", "10.0.0.20", "10.0.0.30"]

    rows = []
    for ts in timestamps:
        num_events = rng.integers(0, 5)
        for _ in range(num_events):
            event_type = rng.choice(EVENT_TYPES, p=[0.45, 0.25, 0.2, 0.10])
            src, ip_risk = _pick_ip(rng, offenders, public_pool, local_pool)
            dest_ip = rng.choice(servers)
            dest_port = int(rng.choice(
                [22, 23, 25, 80, 110, 135, 139, 389, 443, 445, 8080, 8443, 3389, 5900]))
            user = rng.choice(users)

            if event_type == "failed_login":
                status, severity = "failed", "low"
            elif event_type == "successful_login":
                status, severity = "success", "info"
            elif event_type == "port_scan":
                status, severity = "suspicious", "medium"
                dest_port = int(rng.integers(1, 65535))
            else:
                status, severity = "suspicious", "high"

            rows.append({
                "timestamp": ts,
                "src_ip": src,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "username": user,
                "event_type": event_type,
                "status": status,
                "severity": severity,
                "ip_risk": ip_risk
            })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sample(frac=1.0, random_state=seed).sort_values("timestamp").reset_index(drop=True)

def normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.strip().lower() for c in df.columns]
    if "timestamp" not in df.columns:
        raise ValueError("Missing required column: 'timestamp'")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["src_ip", "dest_ip", "dest_port", "username", "event_type", "status", "severity", "ip_risk"]:
        if col not in df.columns:
            df[col] = np.nan
    if df["dest_port"].notna().any():
        df["dest_port"] = pd.to_numeric(df["dest_port"], errors="coerce").astype("Int64")
    df["hour"] = df["timestamp"].dt.hour
    return df.dropna(subset=["timestamp"]).sort_values("timestamp")

def detect_alerts(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["time", "src_ip", "rule", "evidence", "severity"])
    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce")
    alerts = []

    failed = work[work["event_type"] == "failed_login"]
    if not failed.empty:
        g = failed.set_index("timestamp").groupby("src_ip").resample("2min")["event_type"].count()
        bf = g[g >= 6].reset_index().rename(columns={"event_type": "count"})
        for _, r in bf.iterrows():
            alerts.append({
                "time": r["timestamp"],
                "src_ip": r["src_ip"],
                "rule": "Brute Force (>=6/2min)",
                "evidence": f"count={int(r['count'])}",
                "severity": "medium"
            })

    ps = (work.set_index("timestamp").groupby("src_ip").resample("2min")["dest_port"].nunique())
    ps = ps[ps >= 12].reset_index().rename(columns={"dest_port": "unique_ports"})
    for _, r in ps.iterrows():
        alerts.append({
            "time": r["timestamp"],
            "src_ip": r["src_ip"],
            "rule": "Port Scan (>=12 ports/2min)",
            "evidence": f"unique_ports={int(r['unique_ports'])}",
            "severity": "medium"
        })

    sus = work[work["event_type"] == "suspicious_login"]
    for _, r in sus.iterrows():
        alerts.append({
            "time": r["timestamp"],
            "src_ip": r.get("src_ip", ""),
            "rule": "Suspicious Login",
            "evidence": f"user={r.get('username', '')}",
            "severity": "high"
        })

    out = pd.DataFrame(alerts)
    if out.empty:
        return pd.DataFrame(columns=["time", "src_ip", "rule", "evidence", "severity"])
    return out.sort_values("time")

def kpi_card(label, value, sub=""):
    st.markdown(f"""
    <div style="
        padding:16px;
        border-radius:16px;
        background: rgba(124, 44, 191, 0.15);
        border: 1px solid rgba(199, 125, 255, 0.5);
        box-shadow: 0 0 20px rgba(199, 125, 255, 0.6);
        text-align:center;">
      <div style="font-size:14px;opacity:0.8;margin-bottom:6px;">{label}</div>
      <div style="font-size:32px;font-weight:800;line-height:1;color:#EAD7FF;">{value}</div>
      <div style="font-size:13px;opacity:0.65;">{sub}</div>
    </div>
    """, unsafe_allow_html=True)

# =================== Sidebar ===================
with st.sidebar:
    st.markdown("""
    <div style="
        text-align:center; 
        padding:20px 10px; 
        border-bottom:1px solid rgba(255,255,255,0.15);
        background:linear-gradient(180deg, rgba(124,44,191,0.25), rgba(20,12,40,0.6));
        border-radius:12px;
        margin-bottom:15px;">
        <div style="font-size:42px;">🛡️</div>
        <div style="font-weight:800; font-size:17px; margin-top:5px; color:#EAE6FF;">Selvina Swarna</div>
        <div style="font-size:13px; opacity:0.75; font-style:italic;">CyberPulse Dashboard</div>
    </div>
    """, unsafe_allow_html=True)

    # Data source selection
    mode = st.radio("📂 Data Source", ["🧪 Demo Data", "⬆️ Upload CSV"], index=0)

    # Demo data controls
    minutes = st.slider("Demo duration (minutes)", 60, 360, 180)
    step = st.selectbox("Event step (sec)", [15, 30, 60], index=1)

    # File upload
    uploaded = None
    if mode == "⬆️ Upload CSV":
        uploaded = st.file_uploader("Upload CSV", type=["csv"])

# =================== Load Data ===================
if mode == "🧪 Demo Data":
    df = generate_demo_data(minutes=minutes, step_seconds=step, seed=42)
else:
    if uploaded is not None:
        try:
            raw = pd.read_csv(uploaded)
            df = normalize_df(raw)
        except Exception as e:
            st.error(f"⚠️ Error reading CSV: {e}")
            st.stop()
    else:
        st.info("📂 Please upload a CSV file from the sidebar.")
        st.stop()

if df.empty:
    st.warning("⚠️ No events to display. Try increasing demo duration or upload a different dataset.")
    st.stop()

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df = df.dropna(subset=["timestamp"]).sort_values("timestamp")
df["hour"] = df["timestamp"].dt.hour

alerts = detect_alerts(df)

# =================== Header ===================
st.markdown('<div class="header">🧩 CyberPulse Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="subheader">Live detections • Brute force • Port scans • Suspicious logins</div>', unsafe_allow_html=True)

# =================== KPIs ===================
c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    kpi_card("Critical", (df["severity"]=="high").sum(), "Events")
with c2:
    kpi_card("High", (df["severity"]=="medium").sum(), "Events")
with c3:
    kpi_card("Low", (df["severity"]=="low").sum(), "Events")
with c4:
    kpi_card("Events", f"{len(df):,}", "Total processed")
with c5:
    kpi_card("IPs", df["src_ip"].nunique(), "Unique sources")

# =================== Row 1: Heatmap + Map ===================
colA, colB = st.columns((2, 1))
with colA:
    
    pivot_evt = (df.pivot_table(index="event_type", columns="hour", values="src_ip", aggfunc="count")
                   .fillna(0)
                   .reindex(index=["failed_login","successful_login","port_scan","suspicious_login"], fill_value=0))
    fig_evt = px.imshow(
        pivot_evt,
        color_continuous_scale=["#2d0a2d", "#7b2cbf", "#c77dff"],
        labels=dict(x="Hour of Day", y="Event Type", color="Events"),
        aspect="auto",
        title="Event Types by Hour"
    )
    fig_evt.update_layout(template="plotly_dark", margin=dict(l=10,r=10,t=50,b=10))
    st.plotly_chart(fig_evt, use_container_width=True, key="event_heatmap")

with colB:
    
    risk_to_geo = {
        "High": (51.5, 0.1),   # London
        "Medium": (48.8, 2.3), # Paris
        "Low": (40.7, -74.0)   # New York
    }
    geo_df = (df.groupby("ip_risk")["src_ip"].count()
                .reset_index(name="count")
                .assign(lat=lambda x: x["ip_risk"].map({k:v[0] for k,v in risk_to_geo.items()}),
                        lon=lambda x: x["ip_risk"].map({k:v[1] for k,v in risk_to_geo.items()})))
    fig_map = px.scatter_geo(
        geo_df, lat="lat", lon="lon", size="count", color="ip_risk",
        projection="natural earth", title="IP Risk Distribution"
    )
    fig_map.update_traces(marker=dict(opacity=0.8, line=dict(width=2, color="rgba(255,255,255,0.4)")))
    fig_map.update_layout(template="plotly_dark", margin=dict(l=10,r=10,t=50,b=10))
    st.plotly_chart(fig_map, use_container_width=True, key="ip_geo_map")

# =================== Row 2: Trends + Event Type Split ===================
colC, colD = st.columns((2, 1))
with colC:
    trend = df.set_index("timestamp").resample("1min").size().reset_index(name="events")
    fig_line = px.line(trend, x="timestamp", y="events", title="Events per Minute")
    fig_line.update_traces(line=dict(color="#C77DFF", width=2))  # 💜 light purple
    fig_line.update_layout(template="plotly_dark", margin=dict(l=10,r=10,t=50,b=10), font=dict(color="#EAE6FF"))
    st.plotly_chart(fig_line, use_container_width=True, key="events_per_minute")

with colD:
    et = df["event_type"].value_counts().reset_index()
    et.columns = ["event_type", "count"]
    fig_pie = px.pie(
        et,
        values="count",
        names="event_type",
        hole=0.45,
        title="Event Type Split",
        color="event_type",
        color_discrete_map={
            "failed_login": "#636EFA",
            "successful_login": "#EF553B",
            "port_scan": "#00CC96",
            "suspicious_login": "#AB63FA"
        }
    )
    fig_pie.update_traces(textinfo="label+percent")
    fig_pie.update_layout(template="plotly_dark", margin=dict(l=10, r=10, t=50, b=10), font=dict(color="#EAE6FF"))
    st.plotly_chart(fig_pie, use_container_width=True, key="event_type_pie")


