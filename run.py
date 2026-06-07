#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Testing Suite - Launcher
Khoi dong toan bo he thong voi mot lenh duy nhat.

Usage:
    python run.py              -- Khoi dong tat ca
    python run.py --no-browser -- Khong mo browser tu dong
    python run.py --target-only -- Chi khoi dong target server
    python run.py --api-only    -- Chi khoi dong API server
"""

import sys
import os
import time
import subprocess
import threading
import webbrowser
import argparse

# Fix Windows terminal encoding
if sys.platform == 'win32':
    import io
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except AttributeError:
        pass

# --- Colors ---
class C:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    C = '\033[96m'
    W = '\033[97m'
    M = '\033[95m'
    E = '\033[0m'
    BOLD = '\033[1m'


def banner():
    print("""
+--------------------------------------------------------------+
|  [*] Security Testing Suite v2.0                            |
|  WAF Detection + DDoS Simulation Lab                        |
|  [!] Chi dung cho muc dich hoc thuat / kiem thu local       |
+--------------------------------------------------------------+
""")


def find_free_port(start: int, count: int = 20) -> int:
    """Tim port trong khoang [start, start+count] chua duoc dung."""
    import socket
    for port in range(start, start + count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"Khong tim thay port trong khoang {start}-{start+count}")


def check_dependencies():
    """Kiem tra cac package can thiet."""
    required = ['fastapi', 'uvicorn', 'aiohttp', 'flask', 'requests', 'psutil']
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"{C.Y}[!] Thieu packages: {', '.join(missing)}{C.E}")
        print(f"{C.C}[*] Dang cai dat...{C.E}")
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'],
            check=True, capture_output=True
        )
        print(f"{C.G}[+] Cai dat hoan tat!{C.E}")


def wait_for_port(port: int, timeout: float = 10.0) -> bool:
    """Doi cho den khi port available."""
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('localhost', port), timeout=0.5):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.3)
    return False


def stream_output(process: subprocess.Popen, prefix: str, color: str):
    """Stream output tu subprocess."""
    try:
        for line in iter(process.stdout.readline, b''):
            text = line.decode('utf-8', errors='replace').rstrip()
            if text:
                print(f"{color}[{prefix}]{C.E} {text}", flush=True)
        for line in iter(process.stderr.readline, b''):
            text = line.decode('utf-8', errors='replace').rstrip()
            if text and 'INFO' not in text and 'WARNING' not in text:
                print(f"{C.Y}[{prefix}!]{C.E} {text}", flush=True)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description='Security Testing Suite Launcher')
    parser.add_argument('--no-browser', action='store_true', help='Khong mo browser tu dong')
    parser.add_argument('--target-only', action='store_true', help='Chi chay target server')
    parser.add_argument('--api-only', action='store_true', help='Chi chay API server')
    parser.add_argument('--target-port', type=int, default=0, help='Port cho target server (0=auto)')
    parser.add_argument('--api-port', type=int, default=0, help='Port cho API server (0=auto)')
    args = parser.parse_args()

    banner()

    # Thu muc goc
    root_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root_dir)

    # Auto-detect free ports
    target_port = args.target_port if args.target_port else find_free_port(5100)
    api_port    = args.api_port    if args.api_port    else find_free_port(8910)
    print(f"{C.C}[*] Target port: {target_port} | API port: {api_port}{C.E}")

    # Patch dashboard JS thi dong
    app_js_path = os.path.join(root_dir, 'dashboard', 'app.js')
    if os.path.exists(app_js_path):
        with open(app_js_path, 'r', encoding='utf-8') as f:
            js = f.read()
        import re
        js = re.sub(r"const DEFAULT_TARGET = \(\) => 'http://localhost:\d+';", f"const DEFAULT_TARGET = () => 'http://localhost:{target_port}';", js)
        with open(app_js_path, 'w', encoding='utf-8') as f:
            f.write(js)
        print(f"{C.G}[+] Dashboard JS patched{C.E}")

    # Patch HTML defaults
    html_path = os.path.join(root_dir, 'dashboard', 'index.html')
    if os.path.exists(html_path):
        with open(html_path, 'r', encoding='utf-8') as f:
            html = f.read()
        import re
        html = re.sub(r'localhost:\d+"', f'localhost:{target_port}"', html)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"{C.G}[+] Dashboard HTML patched{C.E}")

    # Kiem tra dependencies
    print(f"{C.C}[*] Kiem tra dependencies...{C.E}")
    try:
        check_dependencies()
        print(f"{C.G}[+] Dependencies OK{C.E}")
    except Exception as e:

        print(f"{C.R}[!] Loi dependencies: {e}{C.E}")
        print(f"{C.Y}    Chay thu cong: pip install -r requirements.txt{C.E}")

    processes = []

    try:
        # -- Khoi dong Target Server --
        if not args.api_only:
            print(f"\n{C.G}[+] Khoi dong Target Server -> http://localhost:{target_port}{C.E}")
            target_proc = subprocess.Popen(
                [sys.executable, '-u', os.path.join(root_dir, 'target_server', 'app.py')],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=root_dir,
                env={**os.environ, 'FLASK_PORT': str(target_port)},
            )
            processes.append(('Target Server', target_proc))

            threading.Thread(
                target=stream_output,
                args=(target_proc, 'TARGET', C.G),
                daemon=True
            ).start()

            if wait_for_port(target_port, timeout=8):
                print(f"{C.G}[+] Target Server san sang{C.E}")
            else:
                print(f"{C.Y}[!] Target Server khoi dong cham, tiep tuc...{C.E}")

        # -- Khoi dong API Server --
        if not args.target_only:
            print(f"\n{C.B}[+] Khoi dong API Server -> http://localhost:{api_port}{C.E}")
            api_proc = subprocess.Popen(
                [sys.executable, '-u', '-m', 'uvicorn', 'api_server:app',
                 '--host', '0.0.0.0',
                 '--port', str(api_port),
                 '--log-level', 'warning'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=root_dir,
            )
            processes.append(('API Server', api_proc))

            threading.Thread(
                target=stream_output,
                args=(api_proc, 'API', C.B),
                daemon=True
            ).start()

            if wait_for_port(api_port, timeout=12):
                print(f"{C.G}[+] API Server san sang{C.E}")
            else:
                print(f"{C.Y}[!] API Server khoi dong cham, tiep tuc...{C.E}")

        # -- Mo Browser --
        if not args.no_browser and not args.target_only:
            dashboard_url = f"http://localhost:{api_port}/dashboard"
            print(f"\n{C.M}[*] Mo Dashboard: {dashboard_url}{C.E}")
            time.sleep(1.5)
            webbrowser.open(dashboard_url)

        # -- Summary --
        print(f"""
{C.BOLD}{C.W}+------------------------------------------+{C.E}
{C.BOLD}{C.W}|  He thong dang chay!                     |{C.E}
{C.BOLD}{C.W}+------------------------------------------+{C.E}
{C.BOLD}{C.W}|{C.E}  Target:    {C.G}http://localhost:{target_port:<17}{C.BOLD}{C.W}|{C.E}
{C.BOLD}{C.W}|{C.E}  API:       {C.B}http://localhost:{api_port:<17}{C.BOLD}{C.W}|{C.E}
{C.BOLD}{C.W}|{C.E}  Dashboard: {C.M}http://localhost:{api_port}/dashboard  {C.BOLD}{C.W}|{C.E}
{C.BOLD}{C.W}|{C.E}  API Docs:  {C.C}http://localhost:{api_port}/docs       {C.BOLD}{C.W}|{C.E}
{C.BOLD}{C.W}+------------------------------------------+{C.E}
{C.BOLD}{C.W}|  Nhan Ctrl+C de dung tat ca              |{C.E}
{C.BOLD}{C.W}+------------------------------------------+{C.E}
""")

        # Doi cho den khi user dung
        while True:
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"{C.R}[!] {name} da dung (exit code: {proc.returncode}){C.E}")
            time.sleep(2)

    except KeyboardInterrupt:
        print(f"\n{C.Y}[*] Dang dung tat ca services...{C.E}")

    finally:
        for name, proc in processes:
            print(f"{C.Y}[*] Dung {name}...{C.E}")
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            print(f"{C.G}[+] {name} da dung{C.E}")

        print(f"\n{C.G}[+] Da dung tat ca. Tam biet!{C.E}\n")


if __name__ == '__main__':
    main()
