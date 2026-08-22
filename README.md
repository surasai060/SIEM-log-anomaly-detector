# 🛡️ SIEM Log Anomaly Detector

> A Python tool that automatically detects security threats in firewall and syslog files — simulating the correlation rules used in enterprise SIEM platforms like **IBM QRadar** and **HP ArcSight**.

Built as a SOC analyst portfolio project by **Sai Sura** — Master's student in Intelligent Interactive Systems, Universität Bielefeld.

---

## 📸 Dashboard Preview

```
╔══════════════════════════════════════════════════════════╗
║  🛡️  SIEM Log Anomaly Detector                          ║
║  ─────────────────────────────────────────────────────  ║
║  Total Events: 971   Alerts: 4   Severity: 🔴 HIGH      ║
║  ─────────────────────────────────────────────────────  ║
║                                                          ║
║  🔴 [HIGH]   Brute Force Attack                         ║
║              185.220.101.47 → 40 failed logins / 60s    ║
║                                                          ║
║  🟠 [MEDIUM] Port Scan Detected                         ║
║              45.33.32.156 → 30 ports / 30s              ║
║                                                          ║
║  🟠 [MEDIUM] High Traffic Volume                        ║
║              203.0.113.99 → 600 events                  ║
║                                                          ║
║  🟡 [LOW]    After-Hours Login Attempt                  ║
║              91.108.4.1 → login at 02:17                ║
║                                                          ║
║  [ 📥 Download Incident Report (JSON) ]                 ║
╚══════════════════════════════════════════════════════════╝
```

---

## 🎯 Problem This Solves

In a real Security Operations Center (SOC), analysts manually review **thousands of log lines per day** looking for attack patterns. This is slow, error-prone, and impossible to scale.

This tool **automates the first-pass detection** — the same job that IBM QRadar and HP ArcSight do with their correlation rules — using pure Python. An analyst can drop in a log file and immediately see what needs attention, instead of reading raw text.

---

## 🔍 What It Detects

| Threat | Detection Rule | Severity |
|--------|---------------|----------|
| **Brute Force Attack** | >10 failed logins from same IP within 60 seconds | 🔴 HIGH |
| **Port Scan** | >15 unique ports hit from same IP within 30 seconds | 🟠 MEDIUM |
| **High Traffic / DDoS** | >500 events from a single IP | 🟠 MEDIUM |
| **After-Hours Login** | Authentication attempt outside 08:00–18:00 | 🟡 LOW |

---

## 🏗️ Architecture

```
                    ┌─────────────────┐
                    │   Log File      │
                    │  (syslog/fw)    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Log Parser     │  ← Extracts: timestamp, IP,
                    │  (analyzer.py)  │    port, service, auth status
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │  Brute Force │ │  Port Scan   │ │ High Traffic │
    │  Detector    │ │  Detector    │ │  Detector    │
    └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
              └──────────────┼──────────────┘
                             ▼
                    ┌─────────────────┐
                    │ Report Generator│  ← JSON incident report
                    │                 │    with severity + actions
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │   Streamlit     │  ← Web dashboard
                    │   Dashboard     │
                    └─────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/surasai060/SIEM-log-anomaly-detector.git
cd SIEM-log-anomaly-detector
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate sample logs (with real attack patterns embedded)
```bash
python generate_sample_logs.py
```
This creates `sample_logs/auth.log` with ~970 log entries including a brute force attack, port scan, and flood traffic mixed into normal traffic.

### 4a. Run CLI analysis
```bash
python analyzer.py sample_logs/auth.log report.json
```

### 4b. Launch the Streamlit dashboard
```bash
streamlit run dashboard.py
```
Then open **http://localhost:8501** in your browser.

---

## 📊 Sample Output (CLI)

```
[*] Loading logs from: sample_logs/auth.log
[*] Parsed 971 log events
[*] Running detection engines...
[*] Report saved to: report.json

==================================================
  OVERALL SEVERITY: HIGH
  Alerts Found:     4
==================================================

  [HIGH] Brute Force Attack
  Source IP : 185.220.101.47
  Details   : 40 failed login attempts from 185.220.101.47 within 60s
  Action    : Block IP, review account lockout policy, enable MFA

  [MEDIUM] Port Scan
  Source IP : 45.33.32.156
  Details   : 45.33.32.156 scanned 30 unique ports within 30s
  Action    : Block IP at perimeter firewall, review IDS/IPS rules

  [MEDIUM] High Traffic Volume
  Source IP : 203.0.113.99
  Details   : 203.0.113.99 generated 600 log events (threshold: 500)
  Action    : Investigate for DDoS or data exfiltration

  [LOW] After-Hours Login Attempt
  Source IP : 91.108.4.1
  Details   : Authentication attempt at 02:17 (outside business hours)
  Action    : Verify if legitimate; alert account owner
```

---

## 📄 Sample Incident Report (JSON)

```json
{
  "report_metadata": {
    "tool": "SIEM Log Anomaly Detector",
    "generated_at": "2026-06-27 14:32:01",
    "total_events_analyzed": 971,
    "total_alerts": 4,
    "overall_severity": "HIGH"
  },
  "executive_summary": "4 anomalies detected across 971 log events. Overall risk level: HIGH.",
  "alerts": [
    {
      "type": "Brute Force Attack",
      "severity": "HIGH",
      "src_ip": "185.220.101.47",
      "count": 40,
      "first_seen": "2026-06-27 09:30:00",
      "last_seen": "2026-06-27 09:30:45",
      "recommendation": "Block IP, review account lockout policy, enable MFA"
    }
  ]
}
```

---

## 📁 Project Structure

```
SIEM-log-anomaly-detector/
│
├── analyzer.py                 # Core detection engine
│   ├── Log Parser              #   Parses raw syslog lines
│   ├── Brute Force Detector    #   Threshold: >10 failures/60s
│   ├── Port Scan Detector      #   Threshold: >15 ports/30s
│   ├── High Traffic Detector   #   Threshold: >500 events/IP
│   ├── After-Hours Detector    #   Outside 08:00-18:00
│   └── Report Generator        #   JSON incident report
│
├── dashboard.py                # Streamlit web dashboard
├── generate_sample_logs.py     # Realistic test log generator
├── requirements.txt            # streamlit
└── sample_logs/
    └── auth.log                # Generated test data
```

---

## 🔗 How This Relates to Real SIEM Tools

| This Project | IBM QRadar / HP ArcSight |
|---|---|
| `detect_brute_force()` | "Authentication Failure" correlation rule |
| `detect_port_scan()` | "Port Scan Detected" offense rule |
| `detect_high_traffic()` | "Flow Volume Anomaly" rule |
| JSON incident report | QRadar Offense / ArcSight Case |
| Severity: HIGH/MEDIUM/LOW | QRadar Magnitude 1–10 |

---

## 🛠️ Tech Stack

- **Python 3.x** — log parsing, detection logic, report generation
- **Streamlit** — interactive web dashboard
- **JSON** — structured incident report output
- **Regex** — log line pattern matching

---

## 👤 Author

**Sai Sura**  
Master's in Intelligent Interactive Systems — Universität Bielefeld  
1 year SOC experience — Tech Mahindra (IBM QRadar, HP ArcSight)  
📧 surasai060@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/sai-sura-945032284)

---

## 📜 License

MIT License — free to use, modify, and distribute.
