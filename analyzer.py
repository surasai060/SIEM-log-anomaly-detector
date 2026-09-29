import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
BRUTE_FORCE_THRESHOLD = 10       
BRUTE_FORCE_WINDOW_SEC = 60      
PORT_SCAN_THRESHOLD = 15         
PORT_SCAN_WINDOW_SEC = 30        
HIGH_TRAFFIC_THRESHOLD = 500
HIGH_TRAFFIC_WINDOW_SEC = 600    # 10 minutes

MITRE = {
    'Brute Force Attack': 'T1110 - Brute Force',
    'Port Scan': 'T1046 - Network Service Discovery',
    'High Traffic Volume': 'T1498 - Network Denial of Service',
    'After-Hours Login Attempt': 'T1078 - Valid Accounts (possible misuse)',
}

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>\S+):\s+'
    r'(?P<message>.+)'
)
AUTH_FAIL_PATTERN = re.compile(
    r'(Failed password|authentication failure|Invalid user|FAILED LOGIN)',
    re.IGNORECASE
)
# Only the DESTINATION port (DPT=) is used for port-scan detection.
# SSH lines like "from 1.2.3.4 port 51544" contain the attacker's SOURCE port,
# which changes on every connection and must NOT count as a scanned port.
DST_PORT_PATTERN = re.compile(r'\bDPT=(\d+)', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def parse_timestamp(ts_str, year=None):
    """Parse syslog-style timestamps like 'Jun 27 14:32:01'"""
    if year is None:
        year = datetime.now().year
    try:
        return datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def parse_log_line(line):
    """Parse a single log line into structured fields."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        ips = IP_PATTERN.findall(line)
        return {
            'raw': line,
            'timestamp': None,
            'host': '',
            'service': '',
            'message': line,
            'src_ip': ips[0] if ips else None,
            'dst_ip': ips[1] if len(ips) > 1 else None,
            'dst_port': None,
            'is_auth_failure': bool(AUTH_FAIL_PATTERN.search(line)),
        }
    data = match.groupdict()
    ips = IP_PATTERN.findall(data['message'])
    port_match = DST_PORT_PATTERN.search(data['message'])
    dst_port = int(port_match.group(1)) if port_match else None
    return {
        'raw': line,
        'timestamp': parse_timestamp(data['timestamp']),
        'host': data['host'],
        'service': data['service'],
        'message': data['message'],
        'src_ip': ips[0] if ips else None,
        'dst_ip': ips[1] if len(ips) > 1 else None,
        'dst_port': dst_port,
        'is_auth_failure': bool(AUTH_FAIL_PATTERN.search(data['message'])),
    }
def load_logs(filepath):
    """Load and parse all log lines from a file."""
    events = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)
    return events

def detect_brute_force(events):
    """Detect brute force: >10 failed logins from same IP within 60 seconds."""
    alerts = []
    failures_by_ip = defaultdict(list)

    for event in events:
        if not event.get('is_auth_failure') or not event.get('src_ip'):
            continue
        ts = event['timestamp']
        if ts is None:
            continue
        ip = event['src_ip']
        failures_by_ip[ip].append(ts)

    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()
        for i, ts in enumerate(timestamps):
            window = [t for t in timestamps[i:] if t - ts <= timedelta(seconds=BRUTE_FORCE_WINDOW_SEC)]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    'type': 'Brute Force Attack',
                    'severity': 'HIGH',
                    'src_ip': ip,
                    'count': len(window),
                    'first_seen': ts.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_seen': window[-1].strftime('%Y-%m-%d %H:%M:%S'),
                    'description': f"{len(window)} failed login attempts from {ip} within {BRUTE_FORCE_WINDOW_SEC}s",
                    'recommendation': 'Block IP, review account lockout policy, enable MFA',
                })
                break 

    return alerts

def detect_port_scan(events):
    """Detect port scans: single IP hitting >=15 unique DESTINATION ports within 30 seconds."""
    alerts = []
    port_hits = defaultdict(list)  # ip -> [(timestamp, port)]

    for event in events:
        if not event.get('src_ip') or not event.get('dst_port'):
            continue
        ts = event['timestamp']
        if ts is None:
            continue
        port_hits[event['src_ip']].append((ts, event['dst_port']))

    for ip, hits in port_hits.items():
        hits.sort()
        for i, (ts, _) in enumerate(hits):
            window = [(t, p) for t, p in hits[i:] if t - ts <= timedelta(seconds=PORT_SCAN_WINDOW_SEC)]
            unique_ports = set(p for _, p in window)
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    'type': 'Port Scan',
                    'severity': 'MEDIUM',
                    'src_ip': ip,
                    'unique_ports': len(unique_ports),
                    'ports_sampled': sorted(list(unique_ports))[:20],
                    'first_seen': ts.strftime('%Y-%m-%d %H:%M:%S'),
                    'description': f"{ip} scanned {len(unique_ports)} unique ports within {PORT_SCAN_WINDOW_SEC}s",
                    'recommendation': 'Block IP at perimeter firewall, review IDS/IPS rules',
                })
                break
    return alerts
def detect_high_traffic(events):
    """Detect high volume: >=500 events from a single IP within 10 minutes."""
    alerts = []
    times_by_ip = defaultdict(list)
    for event in events:
        if event.get('src_ip') and event.get('timestamp'):
            times_by_ip[event['src_ip']].append(event['timestamp'])

    window = timedelta(seconds=HIGH_TRAFFIC_WINDOW_SEC)
    for ip, timestamps in times_by_ip.items():
        timestamps.sort()
        left = 0
        for right in range(len(timestamps)):          # sliding window
            while timestamps[right] - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count >= HIGH_TRAFFIC_THRESHOLD:
                # extend to the full burst inside this window for reporting
                last = right
                while last + 1 < len(timestamps) and timestamps[last + 1] - timestamps[left] <= window:
                    last += 1
                count = last - left + 1
                alerts.append({
                    'type': 'High Traffic Volume',
                    'severity': 'MEDIUM',
                    'src_ip': ip,
                    'event_count': count,
                    'first_seen': timestamps[left].strftime('%Y-%m-%d %H:%M:%S'),
                    'last_seen': timestamps[last].strftime('%Y-%m-%d %H:%M:%S'),
                    'description': f"{ip} generated {count} log events within {HIGH_TRAFFIC_WINDOW_SEC // 60} minutes (threshold: {HIGH_TRAFFIC_THRESHOLD})",
                    'recommendation': 'Investigate for DDoS or data exfiltration; consider rate limiting',
                })
                break
    return alerts

def detect_after_hours(events, business_start=8, business_end=18):
    """Flag authentication events outside business hours."""
    alerts = []
    seen_ips = set()

    for event in events:
        if not event.get('is_auth_failure') or not event.get('src_ip'):
            continue
        ts = event['timestamp']
        if ts is None:
            continue
        hour = ts.hour
        ip = event['src_ip']
        if (hour < business_start or hour >= business_end) and ip not in seen_ips:
            seen_ips.add(ip)
            alerts.append({
                'type': 'After-Hours Login Attempt',
                'severity': 'LOW',
                'src_ip': ip,
                'time': ts.strftime('%Y-%m-%d %H:%M:%S'),
                'description': f"Authentication attempt from {ip} at {ts.strftime('%H:%M')} (outside business hours)",
                'recommendation': 'Verify if legitimate; alert account owner',
            })

    return alerts
def assign_overall_severity(alerts):
    if any(a['severity'] == 'HIGH' for a in alerts):
        return 'HIGH'
    if any(a['severity'] == 'MEDIUM' for a in alerts):
        return 'MEDIUM'
    if alerts:
        return 'LOW'
    return 'CLEAN'
def generate_report(alerts, log_file, total_events):
    """Generate a structured JSON incident report."""
    severity = assign_overall_severity(alerts)
    report = {
        'report_metadata': {
            'tool': 'SIEM Log Anomaly Detector',
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'log_file': log_file,
            'total_events_analyzed': total_events,
            'total_alerts': len(alerts),
            'overall_severity': severity,
        },
        'executive_summary': (
            f"{len(alerts)} anomalies detected across {total_events} log events. "
            f"Overall risk level: {severity}."
        ) if alerts else f"No anomalies detected across {total_events} log events.",
        'alerts': alerts,
        'recommendations': list(dict.fromkeys(a['recommendation'] for a in alerts)) if alerts else ['No action required.'],  # unique, keeps HIGH-first order
    }
    return report
def analyze(log_filepath, output_json=None):
    """Main analysis function. Returns the full report dict."""
    print(f"\n[*] Loading logs from: {log_filepath}")
    events = load_logs(log_filepath)
    print(f"[*] Parsed {len(events)} log events")

    print("[*] Running detection engines...")
    alerts = []
    alerts += detect_brute_force(events)
    alerts += detect_port_scan(events)
    alerts += detect_high_traffic(events)
    alerts += detect_after_hours(events)

    for alert in alerts:                      # MITRE ATT&CK mapping
        alert['mitre_technique'] = MITRE.get(alert['type'], 'N/A')

    report = generate_report(alerts, log_filepath, len(events))

    if output_json:
        with open(output_json, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to: {output_json}")

    return report
if __name__ == '__main__':
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else 'sample_logs/auth.log'
    out_file = sys.argv[2] if len(sys.argv) > 2 else 'report.json'
    report = analyze(log_file, out_file)
    print(f"\n{'='*50}")
    print(f"  OVERALL SEVERITY: {report['report_metadata']['overall_severity']}")
    print(f"  Alerts Found:     {report['report_metadata']['total_alerts']}")
    print(f"{'='*50}")
    for alert in report['alerts']:
        print(f"\n  [{alert['severity']}] {alert['type']}")
        print(f"  Source IP : {alert['src_ip']}")
        print(f"  Details   : {alert['description']}")
        print(f"  MITRE     : {alert['mitre_technique']}")
        print(f"  Action    : {alert['recommendation']}")
