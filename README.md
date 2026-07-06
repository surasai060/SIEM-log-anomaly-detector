# SIEM Log Anomaly Detector

A Python based tool that analyzes firewall and syslog files to detect security anomalies simulating the correlation rules used in enterprise SIEM platforms like IBM QRadar and HP ArcSight.

Built as a portfolio project demonstrating SOC analyst skills: log analysis,threat detection,and incident reporting.

What It Detects

| Threat | Rule | Severity |
|--------|------|----------|
| Brute Force Attack | >10 failed logins from same IP within 60s.

🔴 HIGH

| Port Scan | >15 unique ports hit from same IP within 30s.

🟠 MEDIUM

| High Traffic Volume | >500 events from single IP 

🟠 MEDIUM

| After-Hours Login | Auth attempt outside 08:00–18:00

🟡 LOW

```bash
# Clone the Repo

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate sample logs
python generate_sample_logs.py

# 4. Run CLI analysis
python analyzer.py sample_logs/auth.log report.json

# 5. Or launch the Streamlit dashboard
streamlit run dashboard.py

# Dashboard

The Streamlit dashboard lets you:
- Upload any `.log` or `.txt` syslog file
- View detected anomalies with severity classification
- Download a structured JSON incident report

# Project Structure

siem-log-anomaly-detector/
├── analyzer.py              # Core detection engine
├── dashboard.py             # Streamlit web dashboard
├── generate_sample_logs.py  # Realistic test log generator
├── requirements.txt
└── sample_logs/
    └── auth.log             

Sample Output

```
[*] Parsed 941 log events
[*] Running detection engines...
  OVERALL SEVERITY: HIGH
  Alerts Found:     4

  [HIGH] Brute Force Attack
  Source IP : 185.220.101.47
  Details   : 40 failed login attempts within 60s

  [MEDIUM] Port Scan
  Source IP : 45.33.32.156
  Details   : 30 unique ports scanned within 30s

  [MEDIUM] High Traffic Volume
  Source IP : 203.0.113.99
  Details   : 600 log events (threshold: 500)

  [LOW] After-Hours Login Attempt
  Source IP : 91.108.4.1
  Details   : Authentication attempt at 02:17
# Tech Stack

-Python — log parsing,detection logic,report generation
-Streamlit — interactive web dashboard
-JSON — structured incident report output
