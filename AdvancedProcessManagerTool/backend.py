import psutil
import logging
import time

logging.basicConfig(filename='process_manager.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

def log_action(action):
    logging.info(action)

def get_all_users():
    all_users = set()
    for p in psutil.process_iter():
        try:
            all_users.add(p.username())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    all_users = list(all_users)
    all_users.insert(0, "All")
    return all_users

def get_open_window_pids():
    open_window_pids = set()
    try:
        import win32gui, win32process
        def enum_window_callback(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                open_window_pids.add(pid)
        win32gui.EnumWindows(enum_window_callback, None)
    except ImportError:
        return set(p.pid for p in psutil.process_iter())
    return open_window_pids

def get_connections(pid):
    try:
        proc = psutil.Process(pid)
        return [f"{c.laddr.ip}:{c.laddr.port}" for c in proc.connections(kind='inet')]
    except Exception:
        return []
