# blocker/blocker.py
import time
import psutil
import json
import os
from pathlib import Path

BASE = Path(__file__).parent
STATE_FILE = BASE / 'blocklist.json'
LOG_FILE = BASE / 'blocker.log'

DEFAULT_BLOCKLIST = [
    # Example tokens (users should edit these)
    "malicious_extension.exe",
    "badplugin",
]

SLEEP_INTERVAL = 2.0  # seconds between scans


def load_blocklist():
    if not STATE_FILE.exists():
        with open(STATE_FILE, 'w') as f:
            json.dump(DEFAULT_BLOCKLIST, f, indent=2)
        return DEFAULT_BLOCKLIST
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return DEFAULT_BLOCKLIST


def log(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(line)
    print(line, end='')


def matches_blocklist(proc, tokens):
    try:
        name = proc.name().lower()
        cmd = ' '.join(proc.cmdline()).lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    for t in tokens:
        t = t.lower()
        if t in name or t in cmd:
            return True
    return False


def terminate_process(proc):
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
            log(f"Terminated PID={proc.pid} name={proc.name()}")
            return True
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
            log(f"Killed PID={proc.pid} name={proc.name()}")
            return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        log(f"Failed to terminate PID={getattr(proc, 'pid', '?')}: {e}")
    return False


def scan_and_block(tokens):
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if matches_blocklist(proc, tokens):
                if proc.pid == os.getpid():
                    continue
                log(f"Detected blocked process PID={proc.pid} name={proc.name()}")
                terminate_process(proc)
        except Exception:
            pass


def main_loop():
    log('Starting blocker agent')
    while True:
        tokens = load_blocklist()
        scan_and_block(tokens)
        time.sleep(SLEEP_INTERVAL)


if __name__ == '__main__':
    try:
        main_loop()
    except KeyboardInterrupt:
        log('Shutting down')
