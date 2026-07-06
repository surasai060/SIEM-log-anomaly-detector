import streamlit as st
import json
import os
import tempfile
from analyzer import analyze
st.set_page_config(
    page_title="SIEM Log Anomaly Detector",
    page_icon="🛡️",
    layout="wide"
)
st.markdown("""
<style>
.high   { background:#ff4b4b22; border-left:4px solid #ff4b4b; padding:12px; border-radius:4px; margin:8px 0; }
.medium { background:#ffa50022; border-left:4px solid #ffa500; padding:12px; border-radius:4px; margin:8px 0; }
.low    { background:#ffd70022; border-left:4px solid #ffd700; padding:12px; border-radius:4px; margin:8px 0; }
.clean  { background:#00ff0022; border-left:4px solid #00c800; padding:12px; border-radius:4px; margin:8px 0; }
.metric-box { background:#1e2130; padding:20px; border-radius:8px; text-align:center; }
</style>
""", unsafe_allow_html=True)
st.title("🛡️ SIEM Log Anomaly Detector")
st.caption("Upload a syslog/firewall log file to detect brute force, port scans, and suspicious activity.")
with st.sidebar:
    st.header("⚙️ Settings")
    st.markdown("---")
    st.markdown("**Detection Thresholds**")
    st.info("Brute Force: >10 failed logins / 60s")
    st.info("Port Scan: >15 unique ports / 30s")
    st.info("High Traffic: >500 events / IP")
    st.markdown("---")
    st.markdown("**About**")
    st.markdown("Simulates SIEM correlation rules (IBM QRadar / HP ArcSight) using Python-based log analysis.")
col1, col2 = st.columns([2, 1])
with col1:
    uploaded = st.file_uploader("Upload log file (.log, .txt)", type=['log', 'txt'])
with col2:
    use_sample = st.button("🧪 Use Sample Logs", use_container_width=True)
    if use_sample:
        from generate_sample_logs import generate
        generate()
        st.session_state['sample_generated'] = True
report = None
if uploaded:
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name
    with st.spinner("Analyzing logs..."):
        report = analyze(tmp_path)
    os.unlink(tmp_path)
elif st.session_state.get('sample_generated') and os.path.exists('sample_logs/auth.log'):
    with st.spinner("Analyzing sample logs..."):
        report = analyze('sample_logs/auth.log')
if report:
    meta = report['report_metadata']
    severity = meta['overall_severity']
    alerts = report['alerts']
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Events", meta['total_events_analyzed'])
    m2.metric("Alerts Found", meta['total_alerts'])
    m3.metric("Overall Severity", severity)
    m4.metric("Analysis Time", meta['generated_at'].split(' ')[1])
    color = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'CLEAN': 'clean'}[severity]
    icons = {'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟡', 'CLEAN': '🟢'}
    st.markdown(f'<div class="{color}"><strong>{icons[severity]} {severity} RISK</strong> — {report["executive_summary"]}</div>', unsafe_allow_html=True)
    if alerts:
        st.markdown("### 🚨 Detected Anomalies")
        for alert in alerts:
            sev = alert['severity']
            css = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}.get(sev, 'low')
            with st.expander(f"{'🔴' if sev=='HIGH' else '🟠' if sev=='MEDIUM' else '🟡'} [{sev}] {alert['type']} — {alert['src_ip']}"):
                st.markdown(f'<div class="{css}">', unsafe_allow_html=True)
                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**Source IP:** `{alert['src_ip']}`")
                    st.write(f"**Type:** {alert['type']}")
                    if 'first_seen' in alert:
                        st.write(f"**First Seen:** {alert['first_seen']}")
                    if 'last_seen' in alert:
                        st.write(f"**Last Seen:** {alert['last_seen']}")
                with c2:
                    st.write(f"**Description:** {alert['description']}")
                    st.write(f"**Recommendation:** {alert['recommendation']}")
                st.markdown('</div>', unsafe_allow_html=True)
        st.markdown("### 📋 Recommended Actions")
        for rec in report['recommendations']:
            st.markdown(f"- {rec}")
    else:
        st.success("✅ No anomalies detected. Logs appear clean.")
    st.markdown("---")
    st.download_button(
        label="📥 Download Incident Report (JSON)",
        data=json.dumps(report, indent=2),
        file_name=f"incident_report_{meta['generated_at'].replace(' ','_').replace(':','-')}.json",
        mime="application/json"
    )
else:
    st.info("👆 Upload a log file or click 'Use Sample Logs' to run a demo analysis.")
