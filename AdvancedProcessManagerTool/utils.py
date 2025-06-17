import time

def bytes_to_mb(b):
    return round(b / (1024 * 1024), 2)

def get_uptime(create_time):
    uptime = int(time.time() - create_time)
    return f"{uptime//3600}h {(uptime%3600)//60}m"
