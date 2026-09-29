import random
from datetime import datetime, timedelta
USERNAMES = ['root', 'admin', 'ubuntu', 'sai', 'test', 'pi', 'oracle']
HOSTS = ['firewall01', 'webserver01', 'db-server', 'gateway']
SERVICES = ['sshd', 'nginx', 'kernel', 'sudo', 'cron']

LEGIT_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
ATTACKER_BRUTE = "185.220.101.47"
ATTACKER_SCAN = "45.33.32.156"
HIGH_TRAFFIC_IP = "203.0.113.99"
def fmt_ts(dt):
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ")
def make_auth_fail(dt, ip, user):
    host = random.choice(HOSTS)
    return f"{fmt_ts(dt)} {host} sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
def make_auth_ok(dt, ip, user):
    host = random.choice(HOSTS)
    return f"{fmt_ts(dt)} {host} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
def make_port_hit(dt, src_ip, dst_port):
    host = random.choice(HOSTS)
    return f"{fmt_ts(dt)} {host} kernel: [UFW BLOCK] IN=eth0 SRC={src_ip} DST=192.168.1.1 DPT={dst_port} PROTO=TCP"
def make_web_request(dt, ip):
    """Web access line that always contains the client IP (used for the flood)."""
    host = random.choice(['webserver01', 'gateway'])
    path = random.choice(['/index.html', '/login', '/api/data', '/search?q=test', '/images/logo.png'])
    return f"{fmt_ts(dt)} {host} nginx[{random.randint(1000,9999)}]: {ip} - GET {path} HTTP/1.1 200"
def make_normal_traffic(dt, ip):
    host = random.choice(HOSTS)
    service = random.choice(SERVICES)
    messages = [
        f"session opened for user ubuntu by (uid=0)",
        f"pam_unix(sudo:session): session opened",
        f"CRON[{random.randint(1000,9999)}]: (root) CMD (/usr/bin/backup.sh)",
        f"nginx: {ip} - GET /index.html HTTP/1.1 200",
    ]
    return f"{fmt_ts(dt)} {host} {service}[{random.randint(1000,9999)}]: {random.choice(messages)}"
def generate(output_path='sample_logs/auth.log', num_normal=300):
    import os
    os.makedirs('sample_logs', exist_ok=True)
    base_time = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)
    lines = []
    for i in range(num_normal):
        dt = base_time + timedelta(seconds=random.randint(0, 7200))
        ip = random.choice(LEGIT_IPS)
        user = random.choice(USERNAMES[2:])
        if random.random() < 0.1:
            lines.append((dt, make_auth_fail(dt, ip, user)))
        else:
            lines.append((dt, make_auth_ok(dt, ip, user) if random.random() > 0.3 else make_normal_traffic(dt, ip)))

    # Brute force attack:
    attack_start = base_time + timedelta(minutes=30)
    for i in range(40):
        dt = attack_start + timedelta(seconds=random.randint(0, 45))
        user = random.choice(USERNAMES)
        lines.append((dt, make_auth_fail(dt, ATTACKER_BRUTE, user)))
    # Port scan:
    scan_start = base_time + timedelta(minutes=60)
    ports = random.sample(range(1, 65535), 30)
    for i, port in enumerate(ports):
        dt = scan_start + timedelta(seconds=random.randint(0, 20))
        lines.append((dt, make_port_hit(dt, ATTACKER_SCAN, port)))
    # High traffic IP:
    flood_start = base_time + timedelta(minutes=90)
    for i in range(600):
        dt = flood_start + timedelta(seconds=random.randint(0, 600))
        lines.append((dt, make_web_request(dt, HIGH_TRAFFIC_IP)))
    night_dt = base_time.replace(hour=2, minute=17, second=33)
    lines.append((night_dt, make_auth_fail(night_dt, "91.108.4.1", "root")))
    lines.sort(key=lambda x: x[0])
    with open(output_path, 'w') as f:
        for _, line in lines:
            f.write(line + '\n')
    print(f"[*] Generated {len(lines)} log entries → {output_path}")
    return output_path
if __name__ == '__main__':
    generate()
