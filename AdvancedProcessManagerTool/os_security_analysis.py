import psutil
import json
import csv
import datetime
import platform

SUSPICIOUS_PAIRS = [
    ("chrome", "powershell"),
    ("firefox", "cmd"),
    ("explorer", "python"),
    ("cmd", "notepad"),
    ("bash", "top"),
    ("code", "terminal"),
]

def get_process_snapshot():
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'status', 'exe', 'cmdline', 'create_time']):
        try:
            info = proc.info
            parent = None
            try:
                parent = proc.parent()
            except Exception:
                pass
            processes.append({
                'pid': info['pid'],
                'ppid': info['ppid'],
                'name': info['name'],
                'username': info.get('username', ''),
                'status': info.get('status', ''),
                'exe': info.get('exe', ''),
                'cmdline': ' '.join(info['cmdline']) if info.get('cmdline') else '',
                'create_time': datetime.datetime.fromtimestamp(info['create_time']).isoformat() if info.get('create_time') else '',
                'parent_name': parent.name() if parent else '',
                'parent_cmdline': ' '.join(parent.cmdline()) if parent else '',
                'memory_mb': round(proc.memory_info().rss / (1024 * 1024), 1),
                'cpu_percent': proc.cpu_percent(interval=0.03),
                'num_threads': proc.num_threads(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def analyze_snapshot(processes):
    anomalies = []
    for proc in processes:
        parent_name = proc.get('parent_name', '') or ''
        child_name = proc.get('name', '') or ''
        for parent, child in SUSPICIOUS_PAIRS:
            if parent_name.lower().startswith(parent) and child_name.lower().startswith(child):
                anomalies.append(f"PID {proc['pid']}: Suspicious parent-child: {parent_name} -> {child_name}")
        username = proc.get('username')
        if username and username.lower() in ['root', 'administrator'] and child_name.lower() not in ['sshd', 'system', 'services', 'init', 'systemd']:
            anomalies.append(f"PID {proc['pid']}: Running as {username}: {child_name}")
        cmdline = proc.get('cmdline', '')
        if not cmdline or cmdline == child_name:
            anomalies.append(f"PID {proc['pid']}: Missing/odd command line: {child_name}")
        if proc.get('ppid') in [0, 1] and child_name.lower() not in ['init', 'systemd']:
            anomalies.append(f"PID {proc['pid']}: Orphan process (ppid={proc.get('ppid')})")
        status = proc.get('status', '') or ''
        if status.lower() in ['zombie', 'defunct']:
            anomalies.append(f"PID {proc['pid']}: Zombie/defunct process: {child_name}")
        if proc.get('memory_mb', 0) > 512:
            anomalies.append(f"PID {proc['pid']}: High memory usage: {proc['memory_mb']}MB ({child_name})")
        if proc.get('cpu_percent', 0) > 50:
            anomalies.append(f"PID {proc['pid']}: High CPU usage: {proc['cpu_percent']}% ({child_name})")
    return anomalies

def save_snapshot(processes, anomalies, base_filename="os_security_snapshot"):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"{base_filename}_{timestamp}.json"
    csv_path = f"{base_filename}_{timestamp}.csv"
    with open(json_path, "w") as jf:
        json.dump({'processes': processes, 'anomalies': anomalies}, jf, indent=2)
    if processes:
        with open(csv_path, "w", newline='', encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=processes[0].keys())
            writer.writeheader()
            writer.writerows(processes)
    return json_path, csv_path

def run_security_analysis():
    processes = get_process_snapshot()
    anomalies = analyze_snapshot(processes)
    json_path, csv_path = save_snapshot(processes, anomalies)
    return anomalies, json_path, csv_path

if __name__ == "__main__":
    print("Running Security Analysis...")
    anomalies, json_path, csv_path = run_security_analysis()
    if anomalies:
        print("Anomalies Detected:")
        for anomaly in anomalies:
            print(f"- {anomaly}")
    else:
        print("No anomalies detected.")
    print(f"Snapshot saved to:\n  JSON: {json_path}\n  CSV: {csv_path}")