import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from tkinter.scrolledtext import ScrolledText
import threading, csv, subprocess, datetime
import psutil
import os
import json
import platform
from queue import Queue
import random
import time
import matplotlib.pyplot as plt

# Custom theme colors
BG_COLOR = "#f0f0f0"
ACCENT_COLOR = "#4a6fa5"
SECONDARY_COLOR = "#6c757d"
DARK_TEXT = "#212529"
LIGHT_TEXT = "#f8f9fa"
WARNING_COLOR = "#dc3545"
SUCCESS_COLOR = "#28a745"

# Security analysis constants
SUSPICIOUS_PAIRS = [
    ("chrome", "powershell"),
    ("firefox", "cmd"),
    ("explorer", "python"),
    ("cmd", "notepad"),
    ("bash", "top"),
    ("code", "terminal"),
]

# Stub backend functions
def get_all_users():
    return ["All", "user1", "user2"]

def get_open_window_pids(self=None):
    """Return PIDs of user processes, prioritizing desktop apps."""
    pids = set()  # Use set to avoid duplicates
    desktop_apps = [
        'explorer.exe', 'notepad.exe', 'calc.exe', 'mspaint.exe', 'cmd.exe',
        'powershell.exe', 'taskmgr.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe',
        'code.exe', 'winword.exe', 'excel.exe', 'outlook.exe', 'teams.exe', 'chrome',
        'gedit', 'nautilus', 'gnome-terminal', 'firefox', 'chromium', 'code',
        'libreoffice', 'gimp', 'vlc', 'totem', 'evince', 'gnome-calculator'
    ]
    try:
        scanned = 0
        desktop_found = 0
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            scanned += 1
            try:
                pid = proc.info['pid']
                name = proc.info['name'].lower()
                exe = os.path.basename(proc.info['exe']).lower() if proc.info['exe'] else ""
                username = proc.info['username']
                if not username or username.lower() == 'system':
                    continue
                if name in desktop_apps or exe in desktop_apps:
                    pids.add(pid)
                    desktop_found += 1
                else:
                    pids.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                if self:
                    self.show_action(f"Skipped process: {str(e)}")
                continue
        if self:
            if desktop_found > 0:
                self.show_action(f"Detected {desktop_found} desktop processes, total {len(pids)} user processes (scanned {scanned})")
            else:
                self.show_action(f"No desktop processes found. Showing {len(pids)} user processes (scanned {scanned})")
        return list(pids)
    except Exception as e:
        if self:
            self.show_action(f"Error detecting processes: {str(e)}")
        return []

def get_connections(pid):
    return []

def log_action(action):
    print(f"Log: {action}")

def bytes_to_mb(bytes_value):
    return bytes_value / (1024 * 1024)

def get_uptime(create_time):
    try:
        delta = datetime.datetime.now() - datetime.datetime.fromtimestamp(create_time)
        return str(delta).split('.')[0]  # More readable without microseconds
    except Exception:
        return "Unknown"

def check_login(username, password):
    return username == "admin" and password == "password"

# Security Analysis Functions
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

# Scheduling Algorithms
def fcfs(processes):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    current_time = 0
    result = []
    timeline = []
    for p in processes:
        start_time = max(current_time, p['arrival_time'])
        wait_time = start_time - p['arrival_time']
        turnaround_time = wait_time + p['burst_time']
        result.append((p['pid'], wait_time, turnaround_time))
        timeline.append((p['pid'], start_time, start_time + p['burst_time']))
        current_time = start_time + p['burst_time']
    return "FCFS", result, timeline

def sjf(processes):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    current_time = 0
    result = []
    timeline = []
    ready_queue = []
    while processes or ready_queue:
        ready_queue.extend(p for p in processes if p['arrival_time'] <= current_time)
        processes = [p for p in processes if p['arrival_time'] > current_time]
        if ready_queue:
            current = min(ready_queue, key=lambda x: x['burst_time'])
            ready_queue.remove(current)
            start_time = current_time
            wait_time = start_time - current['arrival_time']
            turnaround_time = wait_time + current['burst_time']
            result.append((current['pid'], wait_time, turnaround_time))
            timeline.append((current['pid'], start_time, start_time + current['burst_time']))
            current_time += current['burst_time']
        else:
            current_time += 1
    return "SJF", result, timeline

def priority_scheduling(processes):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    current_time = 0
    result = []
    timeline = []
    ready_queue = []
    while processes or ready_queue:
        ready_queue.extend(p for p in processes if p['arrival_time'] <= current_time)
        processes = [p for p in processes if p['arrival_time'] > current_time]
        if ready_queue:
            current = min(ready_queue, key=lambda x: x['priority'])
            ready_queue.remove(current)
            start_time = current_time
            wait_time = start_time - current['arrival_time']
            turnaround_time = wait_time + current['burst_time']
            result.append((current['pid'], wait_time, turnaround_time))
            timeline.append((current['pid'], start_time, start_time + current['burst_time']))
            current_time += current['burst_time']
        else:
            current_time += 1
    return "Priority", result, timeline

def round_robin(processes, quantum=2):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    queue = [p.copy() for p in processes]
    for p in queue:
        p['remaining'] = p['burst_time']
    current_time = 0
    result = []
    timeline = []
    ready_queue = []
    while queue or ready_queue:
        ready_queue.extend(p for p in queue if p['arrival_time'] <= current_time)
        queue = [p for p in queue if p['arrival_time'] > current_time]
        if ready_queue:
            current = ready_queue.pop(0)
            run_time = min(quantum, current['remaining'])
            timeline.append((current['pid'], current_time, current_time + run_time))
            current['remaining'] -= run_time
            current_time += run_time
            if current['remaining'] == 0:
                wait_time = current_time - current['arrival_time'] - current['burst_time']
                turnaround_time = wait_time + current['burst_time']
                result.append((current['pid'], wait_time, turnaround_time))
            else:
                ready_queue.append(current)
        else:
            current_time += 1
    return "Round Robin", result, timeline

# Shared UI styles
def configure_styles():
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('.', font=("Segoe UI", 10), background=BG_COLOR)
    style.configure('Dash.TFrame', background='white', borderwidth=1, relief='solid', bordercolor='#dee2e6')
    style.configure('Dash.TLabel', font=("Segoe UI", 11, "bold"), foreground=DARK_TEXT, background='white')
    style.configure('Custom.Horizontal.TProgressbar', thickness=15, troughcolor='#e9ecef', background=ACCENT_COLOR)
    style.configure('Warning.Horizontal.TProgressbar', thickness=15, troughcolor='#e9ecef', background=WARNING_COLOR)
    style.configure('TButton', padding=6, borderwidth=0)
    style.configure('Accent.TButton', foreground=LIGHT_TEXT, background=ACCENT_COLOR, font=("Segoe UI", 10, "bold"))
    style.map('Accent.TButton', background=[('active', '#3a5a8a'), ('disabled', '#cccccc')])
    style.configure('Warning.TButton', foreground=LIGHT_TEXT, background=WARNING_COLOR)
    style.map('Warning.TButton', background=[('active', '#c82333'), ('disabled', '#cccccc')])
    style.configure('Switch.TCheckbutton', font=("Segoe UI", 9), foreground=SECONDARY_COLOR)
    style.configure('Card.TFrame', background='white', borderwidth=1, relief='solid', bordercolor='#dee2e6', padding=20)
    style.configure('Treeview', font=("Segoe UI", 10), rowheight=25, background='white', fieldbackground='white', foreground=DARK_TEXT)
    style.configure('Treeview.Heading', font=("Segoe UI", 10, "bold"), background=ACCENT_COLOR, foreground=LIGHT_TEXT, relief='flat')
    style.map('Treeview', background=[('selected', '#e2e8f0')], foreground=[('selected', DARK_TEXT)])
    style.configure('TNotebook', background=BG_COLOR, borderwidth=0)
    style.configure('TNotebook.Tab', padding=(15, 5), font=("Segoe UI", 10, "bold"), background='#e9ecef', foreground=SECONDARY_COLOR)
    style.map('TNotebook.Tab', background=[('selected', 'white')], foreground=[('selected', ACCENT_COLOR)])

class LoginPage(tk.Frame):
    def __init__(self, master, on_login_success):
        super().__init__(master)
        self.master = master
        self.on_login_success = on_login_success
        self.configure(bg=BG_COLOR)
        self.pack(fill='both', expand=True)
        configure_styles()
        self.create_widgets()

    def create_widgets(self):
        self.master.title("Login - Process Manager")
        self.master.geometry("450x350")
        self.master.configure(bg=BG_COLOR)

        container = tk.Frame(self, bg=BG_COLOR)
        container.pack(pady=50, padx=20, fill='both', expand=True)

        title = ttk.Label(container, text="Process Manager", font=("Segoe UI", 24, "bold"), foreground=ACCENT_COLOR, background=BG_COLOR)
        title.pack(pady=(0, 30))

        form = ttk.Frame(container, style='Card.TFrame')
        form.pack(pady=10, padx=20, fill='x')

        ttk.Label(form, text="Username:", font=("Segoe UI", 10), foreground=DARK_TEXT).grid(row=0, column=0, sticky='e', pady=10, padx=5)
        self.username_entry = ttk.Entry(form, font=("Segoe UI", 10))
        self.username_entry.grid(row=0, column=1, pady=10, padx=5, sticky='ew')

        ttk.Label(form, text="Password:", font=("Segoe UI", 10), foreground=DARK_TEXT).grid(row=1, column=0, sticky='e', pady=10, padx=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, show="*", font=("Segoe UI", 10))
        self.password_entry.grid(row=1, column=1, pady=10, padx=5, sticky='ew')

        self.show_password_var = tk.BooleanVar()
        show_pw = ttk.Checkbutton(form, text="Show Password", variable=self.show_password_var, command=self.toggle_password, style='Switch.TCheckbutton')
        show_pw.grid(row=2, column=1, sticky='w', pady=5)

        login_btn = ttk.Button(form, text="Login", command=self.check_login, style='Accent.TButton')
        login_btn.grid(row=3, column=0, columnspan=2, pady=15, sticky='ew')

        self.error_label = ttk.Label(form, text="", foreground=WARNING_COLOR, font=("Segoe UI", 9), background=BG_COLOR)
        self.error_label.grid(row=4, column=0, columnspan=2)

        form.columnconfigure(1, weight=1)
        self.username_entry.focus_set()

    def toggle_password(self):
        self.password_entry.config(show="" if self.show_password_var.get() else "*")

    def check_login(self):
        username = self.username_entry.get().strip()
        password = self.password_var.get()
        if check_login(username, password):
            self.error_label.config(text="")
            self.on_login_success(username)
            self.destroy()
        else:
            self.error_label.config(text="Invalid username or password!")

class ProcessManagerGUI:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title("Advanced Process Manager")
        self.root.geometry("1400x800")
        self.root.minsize(1200, 700)
        self.root.configure(bg=BG_COLOR)

        self.auto_refresh = False
        self.watchlist = set()
        self.recent_actions = []
        self.deadlock_stop_event = threading.Event()
        self.deadlock_output_queue = Queue()

        configure_styles()
        self.setup_ui()
        self.refresh_processes()
        self.update_dashboard()
        self.start_auto_refresh()
        self.check_watchlist()

    def setup_ui(self):
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=10, pady=10)

        dash = ttk.Frame(main_container, style='Dash.TFrame')
        dash.pack(fill='x', pady=(0, 10), ipadx=10, ipady=10)

        cpu_frame = ttk.Frame(dash)
        cpu_frame.pack(side='left', padx=20, pady=5)
        ttk.Label(cpu_frame, text="CPU Usage", style='Dash.TLabel').pack(anchor='w')
        self.cpu_bar = ttk.Progressbar(cpu_frame, style='Custom.Horizontal.TProgressbar', length=150, maximum=100)
        self.cpu_bar.pack(fill='x', pady=(5, 0))
        self.cpu_var = tk.StringVar()
        ttk.Label(cpu_frame, textvariable=self.cpu_var, font=("Segoe UI", 10), background='white').pack()

        ram_frame = ttk.Frame(dash)
        ram_frame.pack(side='left', padx=20, pady=5)
        ttk.Label(ram_frame, text="RAM Usage", style='Dash.TLabel').pack(anchor='w')
        self.ram_bar = ttk.Progressbar(ram_frame, style='Custom.Horizontal.TProgressbar', length=150, maximum=100)
        self.ram_bar.pack(fill='x', pady=(5, 0))
        self.ram_var = tk.StringVar()
        ttk.Label(ram_frame, textvariable=self.ram_var, font=("Segoe UI", 10), background='white').pack()

        proc_frame = ttk.Frame(dash)
        proc_frame.pack(side='left', padx=20, pady=5)
        ttk.Label(proc_frame, text="Running Processes", style='Dash.TLabel').pack(anchor='w')
        self.proc_var = tk.StringVar()
        ttk.Label(proc_frame, textvariable=self.proc_var, font=("Segoe UI", 24, "bold"), foreground=ACCENT_COLOR, background='white').pack(pady=(5, 0))

        user_frame = ttk.Frame(dash)
        user_frame.pack(side='right', padx=20, pady=5)
        ttk.Label(user_frame, text=f"Welcome, {self.username}!", font=("Segoe UI", 11, "italic"), foreground=SUCCESS_COLOR, background='white').pack(anchor='e')
        ttk.Button(user_frame, text="Logout", command=self.logout, style='TButton').pack(anchor='e', pady=(5, 0))

        control_frame = ttk.Frame(main_container)
        control_frame.pack(fill='x', pady=(0, 10))

        search_frame = ttk.LabelFrame(control_frame, text=" Search & Filter ", padding=10)
        search_frame.pack(side='left', fill='x', expand=True, padx=(0, 10))

        self.search_var = tk.StringVar()
        self.status_filter = tk.StringVar(value="All")
        self.user_filter = tk.StringVar(value="All")

        ttk.Entry(search_frame, textvariable=self.search_var, width=30, font=("Segoe UI", 10)).pack(side='left', padx=5)
        ttk.Label(search_frame, text="Status:").pack(side='left', padx=(10, 5))
        ttk.Combobox(search_frame, textvariable=self.status_filter, values=["All", "Running", "Sleeping"], width=10, state="readonly").pack(side='left')
        ttk.Label(search_frame, text="User:").pack(side='left', padx=(10, 5))
        all_users = get_all_users()
        ttk.Combobox(search_frame, textvariable=self.user_filter, values=all_users, width=15, state="readonly").pack(side='left')
        ttk.Button(search_frame, text="Search", command=self.search_processes, style='Accent.TButton').pack(side='left', padx=10)
        ttk.Button(search_frame, text="Clear", command=self.refresh_processes).pack(side='left', padx=5)

        # Add button for entering scheduling input
        ttk.Button(control_frame, text="Scheduling Input", command=self.get_processes_from_user, style='Accent.TButton').pack(side='left', padx=10)

        refresh_frame = ttk.Frame(control_frame)
        refresh_frame.pack(side='right')
        self.auto_refresh_btn = ttk.Button(refresh_frame, text="Auto-Refresh: OFF", command=self.toggle_auto_refresh, style='Accent.TButton')
        self.auto_refresh_btn.pack(side='right')

        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill='both', expand=True)

        notebook = ttk.Notebook(content_frame)
        notebook.pack(fill='both', expand=True)

        # Process List Tab
        process_frame = ttk.Frame(notebook)
        notebook.add(process_frame, text="Process List")

        tree_frame = ttk.Frame(process_frame)
        tree_frame.pack(fill='both', expand=True, side='left', pady=(0, 10))

        columns = ('PID', 'Name', 'CPU%', 'Memory', 'Status', 'Uptime', 'User')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode="extended")
        col_widths = [80, 180, 80, 100, 100, 100, 120]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor='center')
        self.tree.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        self.tree.bind("<Double-1>", self.show_details)
        self.tree.bind("<Button-3>", self.add_to_watchlist)

        btn_frame = ttk.Frame(process_frame)
        btn_frame.pack(fill='y', side='right', padx=(10, 0))
        action_btns = [
            ("Start App", self.start_selected_app, 'Accent.TButton'),
            ("Terminate", self.terminate_process, 'Warning.TButton'),
            ("Suspend", self.suspend_process, 'TButton'),
            ("Resume", self.resume_process, 'TButton'),
            ("Set Priority", self.set_priority, 'TButton'),
            ("Export CSV", self.export_csv, 'TButton'),
            ("Scheduler Sim", self.open_scheduler_simulator, 'Accent.TButton'),
            ("Refresh", self.refresh_processes, 'TButton')
        ]
        for text, cmd, style_name in action_btns:
            btn = ttk.Button(btn_frame, text=text, command=cmd, style=style_name, width=15)
            btn.pack(fill='x', pady=3)

        # Security Analysis Tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security Analysis")
        
        security_btn_frame = ttk.Frame(security_frame)
        security_btn_frame.pack(fill='x', pady=5)
        
        ttk.Button(security_btn_frame, text="Run Security Analysis", command=self.run_security_analysis, 
                  style='Accent.TButton').pack(side='left', padx=5)
        
        self.security_output_text = ScrolledText(security_frame, wrap='word', font=("Consolas", 10), height=20)
        self.security_output_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.security_output_text.insert('1.0', "Security analysis results will appear here...")
        self.security_output_text.config(state='disabled')

        actions_frame = ttk.LabelFrame(main_container, text=" Recent Actions ", padding=10)
        actions_frame.pack(fill='x')
        self.actions_text = tk.Text(actions_frame, height=4, state='disabled', font=("Segoe UI", 9), bg='white', padx=10, pady=10, wrap='word')
        self.actions_text.pack(fill='x')

    # Scheduling input dialog
    def get_processes_from_user(self):
        process_input_window = tk.Toplevel(self.root)
        process_input_window.title("Input Processes")
        process_input_window.geometry("400x350")
        process_input_window.grab_set()

        process_list = []

        frame = ttk.Frame(process_input_window, padding=10)
        frame.pack(fill='both', expand=True)

        # Entries for process data
        ttk.Label(frame, text="Process ID:").grid(row=0, column=0, sticky='w')
        pid_entry = ttk.Entry(frame)
        pid_entry.grid(row=0, column=1)

        ttk.Label(frame, text="Arrival Time:").grid(row=1, column=0, sticky='w')
        arrival_entry = ttk.Entry(frame)
        arrival_entry.grid(row=1, column=1)

        ttk.Label(frame, text="Burst Time:").grid(row=2, column=0, sticky='w')
        burst_entry = ttk.Entry(frame)
        burst_entry.grid(row=2, column=1)

        ttk.Label(frame, text="Priority:").grid(row=3, column=0, sticky='w')
        priority_entry = ttk.Entry(frame)
        priority_entry.grid(row=3, column=1)

        # Listbox to show added processes
        processes_listbox = tk.Listbox(frame, height=8)
        processes_listbox.grid(row=4, column=0, columnspan=2, pady=10, sticky='ew')

        def add_process():
            pid = pid_entry.get().strip()
            arrival = arrival_entry.get().strip()
            burst = burst_entry.get().strip()
            priority = priority_entry.get().strip()
            if not pid:
                messagebox.showwarning("Input Error", "Process ID is required.")
                return
            try:
                arrival_time = int(arrival)
                burst_time = int(burst)
                priority_val = int(priority)
            except ValueError:
                messagebox.showwarning("Input Error", "Arrival Time, Burst Time and Priority must be integers.")
                return
            process = {'pid': pid, 'arrival_time': arrival_time, 'burst_time': burst_time, 'priority': priority_val}
            process_list.append(process)
            processes_listbox.insert(tk.END, f"{pid} | Arrival: {arrival_time} | Burst: {burst_time} | Priority: {priority_val}")
            pid_entry.delete(0, tk.END)
            arrival_entry.delete(0, tk.END)
            burst_entry.delete(0, tk.END)
            priority_entry.delete(0, tk.END)
            self.show_action(f"Added process {pid}")

        def submit_processes():
            if not process_list:
                messagebox.showwarning("Input Error", "Add at least one process!")
                return
            process_input_window.destroy()
            self.run_scheduling(process_list)

        add_button = ttk.Button(frame, text="Add Process", command=add_process)
        add_button.grid(row=5, column=0, pady=5)

        submit_button = ttk.Button(frame, text="Run Scheduling", command=submit_processes)
        submit_button.grid(row=5, column=1, pady=5)

    def run_scheduling(self, processes):
        algo_window = tk.Toplevel(self.root)
        algo_window.title("Select Scheduling Algorithm")
        algo_window.geometry("300x220")
        algo_window.grab_set()

        def run_fcfs():
            name, result, timeline = fcfs(processes)
            self.show_results(name, result, timeline)
            algo_window.destroy()

        def run_sjf():
            name, result, timeline = sjf(processes)
            self.show_results(name, result, timeline)
            algo_window.destroy()

        def run_priority():
            name, result, timeline = priority_scheduling(processes)
            self.show_results(name, result, timeline)
            algo_window.destroy()

        def run_round_robin():
            quantum = simpledialog.askinteger("Time Quantum", "Enter time quantum for Round Robin:", minvalue=1, parent=algo_window)
            if quantum is not None:
                name, result, timeline = round_robin(processes, quantum)
                self.show_results(name, result, timeline)
                algo_window.destroy()

        ttk.Button(algo_window, text="First-Come, First-Served (FCFS)", command=run_fcfs).pack(pady=5, fill='x', padx=10)
        ttk.Button(algo_window, text="Shortest Job First (SJF)", command=run_sjf).pack(pady=5, fill='x', padx=10)
        ttk.Button(algo_window, text="Priority Scheduling", command=run_priority).pack(pady=5, fill='x', padx=10)
        ttk.Button(algo_window, text="Round Robin", command=run_round_robin).pack(pady=5, fill='x', padx=10)

    def show_results(self, name, result, timeline):
        result_window = tk.Toplevel(self.root)
        result_window.title(f"{name} Scheduling Results")
        result_window.geometry("600x400")

        result_text = ScrolledText(result_window, wrap='word', font=("Consolas", 10))
        result_text.pack(expand=True, fill='both')

        avg_wait = sum(wait for _, wait, _ in result) / len(result) if result else 0
        avg_turnaround = sum(tat for _, _, tat in result) / len(result) if result else 0

        result_text.insert(tk.END, f"{name} Scheduling Results:\n\n")
        result_text.insert(tk.END, "PID     Wait Time     Turnaround Time\n")
        result_text.insert(tk.END, "-"*40 + "\n")
        for pid, wait, turnaround in result:
            result_text.insert(tk.END, f"{pid:<8}{wait:<14}{turnaround:<16}\n")
        result_text.insert(tk.END, f"\nAverage Wait Time: {avg_wait:.2f}\n")
        result_text.insert(tk.END, f"Average Turnaround Time: {avg_turnaround:.2f}\n\n")

        result_text.insert(tk.END, "Execution Timeline (Gantt Chart Data):\n")
        for pid, start, end in timeline:
            result_text.insert(tk.END, f"Process {pid} from {start} to {end}\n")

        # Show Gantt chart plot
        def plot_chart():
            fig, ax = plt.subplots(figsize=(10, 2 + 0.5*len(timeline)))
            colors = plt.cm.tab20.colors
            for i, (pid, start, end) in enumerate(timeline):
                ax.broken_barh([(start, end - start)], (i * 10, 9), facecolors=colors[i % len(colors)], edgecolors='black')
                ax.text(start + (end - start)/2, i*10+4.5, pid, ha='center', va='center', color='black', fontsize=9)
            ax.set_ylim(0, len(timeline)*10)
            ax.set_xlabel("Time")
            ax.set_yticks([i*10+4.5 for i in range(len(timeline))])
            ax.set_yticklabels([pid for pid, _, _ in timeline])
            ax.set_title(f"Gantt Chart - {name} Scheduling")
            plt.tight_layout()
            plt.show()

        ttk.Button(result_window, text="Show Gantt Chart", command=plot_chart).pack(pady=5)

    def run_security_analysis(self):
        try:
            self.security_output_text.config(state='normal')
            self.security_output_text.delete(1.0, tk.END)
            self.security_output_text.insert(tk.END, "Running security analysis...\n")
            self.security_output_text.see(tk.END)
            self.security_output_text.update()
            
            anomalies, json_path, csv_path = run_security_analysis()
            
            self.security_output_text.delete(1.0, tk.END)
            if anomalies:
                self.security_output_text.insert(tk.END, "Security Anomalies Detected:\n\n")
                for anomaly in anomalies:
                    self.security_output_text.insert(tk.END, f"- {anomaly}\n")
            else:
                self.security_output_text.insert(tk.END, "No security anomalies detected.\n")
            
            self.security_output_text.insert(tk.END, f"\nSnapshot saved to:\n- JSON: {json_path}\n- CSV: {csv_path}\n")
            self.security_output_text.config(state='disabled')
            self.security_output_text.see(tk.END)
            self.show_action(f"Security analysis completed. Saved to {json_path}, {csv_path}")
        except Exception as e:
            self.security_output_text.insert(tk.END, f"\nError running security analysis: {str(e)}\n")
            self.security_output_text.config(state='disabled')
            self.security_output_text.see(tk.END)
            self.show_action(f"Error in security analysis: {str(e)}")

    def update_dashboard(self):
        try:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            procs = len(get_open_window_pids(self))
            self.cpu_var.set(f"{cpu}%")
            self.ram_var.set(f"{ram}%")
            self.proc_var.set(str(procs))
            self.cpu_bar['value'] = cpu
            self.ram_bar['value'] = ram
            self.cpu_bar.configure(style='Warning.Horizontal.TProgressbar' if cpu > 90 else 'Custom.Horizontal.TProgressbar')
            self.ram_bar.configure(style='Warning.Horizontal.TProgressbar' if ram > 90 else 'Custom.Horizontal.TProgressbar')
            if cpu > 90 or ram > 90:
                self.show_action(f"ALERT: High resource usage! CPU: {cpu}%, RAM: {ram}%")
        except Exception as e:
            self.show_action(f"Error updating dashboard: {e}")
        self.root.after(1500, self.update_dashboard)

    def refresh_processes(self):
        def load_and_update():
            try:
                desktop_pids = set(get_open_window_pids(self))
                self.tree.delete(*self.tree.get_children())
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'username', 'create_time', 'status']):
                    if proc.info['pid'] not in desktop_pids:
                        continue
                    try:
                        uptime = get_uptime(proc.info['create_time'])
                        username = proc.info['username'] or "Unknown"
                        self.tree.insert('', 'end', values=(
                            proc.info['pid'],
                            proc.info['name'],
                            f"{proc.info['cpu_percent']:.1f}%",
                            f"{bytes_to_mb(proc.info['memory_info'].rss):.1f} MB",
                            proc.info['status'].capitalize(),
                            uptime,
                            username
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        self.show_action(f"Error displaying process {proc.info['pid']}: {str(e)}")
            except Exception as e:
                self.show_action(f"Error refreshing processes: {str(e)}")
        threading.Thread(target=load_and_update, daemon=True).start()

    def search_processes(self):
        search_term = self.search_var.get().strip().lower()
        status_filter = self.status_filter.get()
        user_filter = self.user_filter.get()
        desktop_pids = set(get_open_window_pids(self))
        self.tree.delete(*self.tree.get_children())
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'username', 'create_time', 'status']):
            if proc.info['pid'] not in desktop_pids:
                continue
            try:
                pid_str = str(proc.info['pid'])
                name_str = proc.info['name'].lower()
                status = proc.info['status'].capitalize()
                username = proc.info['username'] or "Unknown"
                if search_term and not (search_term in name_str or search_term == pid_str):
                    continue
                if status_filter != "All" and status != status_filter:
                    continue
                if user_filter != "All" and username != user_filter:
                    continue
                uptime = get_uptime(proc.info['create_time'])
                self.tree.insert('', 'end', values=(
                    proc.info['pid'], proc.info['name'], f"{proc.info['cpu_percent']:.1f}%",
                    f"{bytes_to_mb(proc.info['memory_info'].rss):.1f} MB", status, uptime, username
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.show_action(f"Error searching process {proc.info['pid']}: {str(e)}")
        self.show_action(f"Search completed: term='{search_term}', status={status_filter}, user={user_filter}")

    def get_selected_pids(self):
        return [self.tree.item(item)['values'][0] for item in self.tree.selection()]

    def terminate_process(self):
        pids = self.get_selected_pids()
        if not pids:
            messagebox.showwarning("Warning", "No processes selected!")
            return
        if not messagebox.askyesno("Confirm", f"Terminate {len(pids)} process(es)?"):
            return
        for pid in pids:
            try:
                psutil.Process(pid).terminate()
                self.show_action(f"Terminated process {pid}")
                log_action(f"Terminated process {pid}")
            except Exception as e:
                self.show_action(f"Error terminating {pid}: {e}")
        self.refresh_processes()

    def suspend_process(self):
        pids = self.get_selected_pids()
        if not pids:
            messagebox.showwarning("Warning", "No processes selected!")
            return
        for pid in pids:
            try:
                psutil.Process(pid).suspend()
                self.show_action(f"Suspended process {pid}")
                log_action(f"Suspended process {pid}")
            except Exception as e:
                self.show_action(f"Error suspending {pid}: {e}")
        self.refresh_processes()

    def resume_process(self):
        pids = self.get_selected_pids()
        if not pids:
            messagebox.showwarning("Warning", "No processes selected!")
            return
        for pid in pids:
            try:
                psutil.Process(pid).resume()
                self.show_action(f"Resumed process {pid}")
                log_action(f"Resumed process {pid}")
            except Exception as e:
                self.show_action(f"Error resuming {pid}: {e}")
        self.refresh_processes()

    def set_priority(self):
        pids = self.get_selected_pids()
        if not pids:
            messagebox.showwarning("Warning", "No processes selected!")
            return
        priority = simpledialog.askinteger("Set Priority", "Enter priority (0-20, lower is higher priority):", minvalue=0, maxvalue=20, initialvalue=10)
        if priority is not None:
            for pid in pids:
                try:
                    psutil.Process(pid).nice(priority)
                    self.show_action(f"Set priority {priority} for process {pid}")
                    log_action(f"Set priority {priority} for process {pid}")
                except Exception as e:
                    self.show_action(f"Error setting priority for {pid}: {e}")

    def show_details(self, event=None):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Details", "Select a process.")
            return
        pid = self.tree.item(sel[0])['values'][0]
        try:
            proc = psutil.Process(pid)
            info = (
                f"Name: {proc.name()}\nStatus: {proc.status()}\nExecutable: {proc.exe()}\n"
                f"Started: {datetime.datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"CPU Usage: {proc.cpu_percent()}%\nMemory: {round(proc.memory_info().rss/(1024*1024),1)} MB\n"
                f"Threads: {proc.num_threads()}\nUser: {proc.username()}\nUptime: {get_uptime(proc.create_time())}\n"
                f"Command Line: {' '.join(proc.cmdline())}\n"
            )
            connections = get_connections(pid)
            if connections:
                info += f"Network Connections: {', '.join(connections)}\n"
            detail_win = tk.Toplevel(self.root)
            detail_win.title(f"Process Details - PID {pid}")
            detail_win.geometry("500x400")
            detail_win.configure(bg=BG_COLOR)
            container = ttk.Frame(detail_win)
            container.pack(fill='both', expand=True, padx=10, pady=10)
            info_frame = ttk.LabelFrame(container, text=" Process Information ", padding=10)
            info_frame.pack(fill='both', expand=True)
            text_frame = ttk.Frame(info_frame)
            text_frame.pack(fill='both', expand=True)
            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side='right', fill='y')
            text_widget = tk.Text(text_frame, wrap='word', yscrollcommand=scrollbar.set, font=("Segoe UI", 10), bg='white', padx=10, pady=10)
            text_widget.insert('1.0', info)
            text_widget.config(state='disabled')
            text_widget.pack(side='left', fill='both', expand=True)
            scrollbar.config(command=text_widget.yview)
        except Exception as e:
            messagebox.showerror("Error", f"Could not get details: {e}")

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save CSV Report As")
        if file_path:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["PID", "Name", "CPU%", "Memory", "Status", "Uptime", "User"])
                for item in self.tree.get_children():
                    writer.writerow(self.tree.item(item)['values'])
            self.show_action(f"Exported CSV to {file_path}")
            log_action(f"Exported CSV to {file_path}")

    def start_selected_app(self):
        app_name = simpledialog.askstring("Start Application", "Enter application name or path:", parent=self.root)
        if app_name:
            self.launch_app(app_name, app_name)

    def launch_app(self, exe_path, app_name):
        try:
            # Try to launch common applications by name
            if app_name.lower() == 'notepad':
                subprocess.Popen(['notepad.exe'])
            elif app_name.lower() == 'calc':
                subprocess.Popen(['calc.exe'])
            elif app_name.lower() == 'mspaint':
                subprocess.Popen(['mspaint.exe'])
            elif app_name.lower() == 'word':
                subprocess.Popen(['winword.exe'])
            elif app_name.lower() == 'excel':
                subprocess.Popen(['excel.exe'])
            elif app_name.lower() == 'chrome':
                subprocess.Popen(['chrome.exe'])
            elif app_name.lower() == 'firefox':
                subprocess.Popen(['firefox.exe'])
            elif app_name.lower() == 'explorer':
                subprocess.Popen(['explorer.exe'])
            elif os.path.exists(exe_path):
                # If it's a full path, try to execute it
                subprocess.Popen([exe_path])
            else:
                # Try to find the executable in system paths
                if platform.system() == 'Windows':
                    # On Windows, try to use 'start' command
                    subprocess.Popen(['start', app_name], shell=True)
                else:
                    # On Unix-like systems, try to execute directly
                    subprocess.Popen([app_name])
            
            self.show_action(f"Started {app_name}")
            log_action(f"Started {app_name}")
            self.refresh_processes()
        except Exception as e:
            messagebox.showerror("Error", f"Could not start {app_name}: {e}")
            self.show_action(f"Failed to start {app_name}: {e}")

    def toggle_auto_refresh(self):
        self.auto_refresh = not self.auto_refresh
        self.auto_refresh_btn.config(text=f"Auto-Refresh: {'ON' if self.auto_refresh else 'OFF'}")
        self.show_action(f"Auto-Refresh {'ON' if self.auto_refresh else 'OFF'}")
        if self.auto_refresh:
            self.start_auto_refresh()

    def start_auto_refresh(self):
        if self.auto_refresh:
            self.refresh_processes()
            self.root.after(5000, self.start_auto_refresh)

    def add_to_watchlist(self, event):
        sel = self.tree.identify_row(event.y)
        if sel:
            pid = self.tree.item(sel)['values'][0]
            self.watchlist.add(pid)
            self.show_action(f"Added PID {pid} to watchlist")

    def check_watchlist(self):
        for pid in list(self.watchlist):
            if not psutil.pid_exists(pid):
                self.show_action(f"Watchlist: Process {pid} terminated!")
                self.watchlist.remove(pid)
        self.root.after(3000, self.check_watchlist)

    def show_action(self, msg):
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        action = f"{timestamp} - {msg}"
        if action not in self.recent_actions:
            self.recent_actions.append(action)
            if len(self.recent_actions) > 5:
                self.recent_actions = self.recent_actions[-5:]
            self.actions_text.config(state='normal')
            self.actions_text.delete('1.0', tk.END)
            self.actions_text.insert('end', '\n'.join(self.recent_actions))
            self.actions_text.config(state='disabled')

    def logout(self):
        self.root.destroy()
        main()

    def open_scheduler_simulator(self):
        self.get_processes_from_user()

def main():
    root = tk.Tk()
    login_page = LoginPage(root, lambda username: ProcessManagerGUI(root, username))
    root.mainloop()

if __name__ == "__main__":
    main()