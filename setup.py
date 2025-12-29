import os
import sys
import time
import json
import shutil
import subprocess
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from datetime import datetime, timezone



# run.py - Add at line 1-2 (very first lines)
import sys
import os

# Force UTF-8 encoding for Windows console - MUST BE FIRST
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# --------------------------
# Basic configuration
# --------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
VENV_DIR = PROJECT_ROOT / "venv_rguard"
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / f"launcher_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.log"
CONFIG_FILE = PROJECT_ROOT / "config.json"
ENV_FILE = PROJECT_ROOT / ".env"

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 8000,
    "auto_open_browser": True,
    "auto_install_dependencies": True,
    "service_install_on_first_run": False,
    "service_name": "RansomGuardService",
    "auto_git_pull": True,
    "required_packages": [
        "fastapi", "uvicorn[standard]", "websockets", "psutil", "watchdog",
        "aiosqlite", "scikit-learn", "numpy", "pydantic","pandas", "lightgbm","xgboost"
    ],
    "max_start_retries": 3,
    "enable_crash_reporter": False,
    "crash_report_port": 9999
}

# --------------------------
# Logging
# --------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
)
logger = logging.getLogger("rguard.launcher")

# --------------------------
# Utils
# --------------------------
def color(text: str, c: str) -> str:
    codes = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
             "cyan": "\033[96m", "blue": "\033[94m", "end": "\033[0m"}
    return codes.get(c, "") + text + codes["end"]

def is_windows():
    return os.name == "nt"

def is_admin():
    if not is_windows():
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_cmd(cmd: List[str], check=False):
    try:
        return subprocess.run(cmd, check=check).returncode
    except:
        return -1
    
#PORT AVIALIABILITY CHECKING    

def is_port_available(host: str, port: int) -> bool:
    """Check if port is available"""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            return True
    except OSError:
        return False
# --------------------------
# Config Loader
# --------------------------
def load_config() -> Dict:
    cfg = DEFAULT_CONFIG.copy()

    if CONFIG_FILE.exists():
        try:
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            cfg.update(loaded)
            logger.info("Loaded config.json")
        except Exception as e:
            logger.error("Error parsing config.json: %s", e)

    if ENV_FILE.exists():
        try:
            for line in ENV_FILE.read_text().splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1)
                    if k in cfg:
                        if v.lower() in ("true", "false"):
                            cfg[k] = v.lower() == "true"
                        else:
                            try:
                                cfg[k] = int(v)
                            except:
                                cfg[k] = v
            logger.info("Loaded .env overrides")
        except Exception as e:
            logger.warning("Failed to load .env: %s", e)

    return cfg

# --------------------------
# Venv
# --------------------------
def ensure_venv_and_reexec():
    current_prefix = Path(sys.prefix).resolve()
    if VENV_DIR.resolve() in current_prefix.parents or current_prefix == VENV_DIR.resolve():
        return

    import venv
    if not VENV_DIR.exists():
        logger.info("Creating venv_rguard...")
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)

    python = VENV_DIR / ("Scripts/python.exe" if is_windows() else "bin/python")
    os.execv(str(python), [str(python), str(Path(__file__).resolve())] + sys.argv[1:])

# --------------------------
# Dependency Installer
# --------------------------
def install_packages(packages: List[str]):
    """Install packages only if missing"""
    import importlib.util
    
    missing = []
    for p in packages:
        # Map package name to import name (e.g., scikit-learn -> sklearn)
        import_name = p.replace("-", "_")
        if import_name == "scikit_learn":
            import_name = "sklearn"
        
        if importlib.util.find_spec(import_name) is None:
            missing.append(p)
    
    if missing:
        logger.info("Installing missing packages: %s", ", ".join(missing))
        run_cmd([sys.executable, "-m", "pip", "install"] + missing)
    else:
        logger.info(" All dependencies already installed")


# --------------------------
# Git Auto Update (safe)
# --------------------------
def safe_git_pull():
    if not (PROJECT_ROOT / ".git").exists():
        logger.info("No git repo found.")
        return True
    logger.info("Running: git pull")
    return run_cmd(["git", "-C", str(PROJECT_ROOT), "pull"]) == 0

# --------------------------
# System Snapshot
# --------------------------
def print_system_snapshot():
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.4)
        mem = psutil.virtual_memory()
        logger.info("CPU: %.1f%%, RAM: %.1f%%", cpu, mem.percent)
    except:
        logger.info("psutil not available.")

# --------------------------
# Crash Reporter
# --------------------------
def start_local_crash_server(port: int):
    import http.server, socketserver

    class CrashHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length).decode("utf-8")
            logger.error("CRASH REPORT: %s", data)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args): return

    def serve():
        with socketserver.TCPServer(("127.0.0.1", port), CrashHandler) as httpd:
            logger.info("Crash server running on 127.0.0.1:%s", port)
            httpd.serve_forever()

    threading.Thread(target=serve, daemon=True).start()

# --------------------------
# Banner
# --------------------------
def animated_banner():
    print(color("RansomGuard — Starting…", "cyan"))
    spinner = "|/-\\"
    steps = ["Checking environment", "Loading config", "Preparing venv", "Installing deps", "Starting backend"]
    for s in steps:
        for i in range(10):
            sys.stdout.write(f"\r{spinner[i % 4]} {s}")
            sys.stdout.flush()
            time.sleep(0.06)
    print("\r")

# --------------------------
# Backend Starter
# --------------------------
def start_backend_with_retries(cfg: Dict):
    """Start backend with retry logic"""
    host = cfg["host"]
    port = cfg["port"]
    retries = cfg["max_start_retries"]
    
    # Add backend to path ONCE before loop
    backend_path = str(PROJECT_ROOT / "backend")
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)
    
    for attempt in range(1, retries + 1):
        try:
            logger.info("Starting backend (attempt %d/%d)...", attempt, retries)
            
            # Import uvicorn first
            import uvicorn
            
            # Start uvicorn with string reference 
            uvicorn.run(
                "main:app", 
                host=host,
                port=port,
                reload=False,
                log_level="info"
            )
            
            # If uvicorn returns, server stopped gracefully
            logger.info("Backend stopped normally")
            return True
            
        except KeyboardInterrupt:
            logger.info("User interrupted backend")
            return True
            
        except Exception as e:
            logger.exception("Backend crashed: %s", e)
            if attempt < retries:
                logger.warning("Retrying in 3 seconds...")
                time.sleep(3)
            else:
                logger.error("Max retries reached")
                return False
    
    return False



# --------------------------
# Main
# --------------------------
def main():
    try:
        animated_banner()
        cfg = load_config()

        ensure_venv_and_reexec()

        if cfg["auto_install_dependencies"]:
            install_packages(cfg["required_packages"])

        print_system_snapshot()

        if cfg["auto_git_pull"]:
            safe_git_pull()

        if cfg["enable_crash_reporter"]:
            start_local_crash_server(cfg["crash_report_port"])

        if cfg["auto_open_browser"]:
            import webbrowser
            url = f"http://{cfg['host']}:{cfg['port']}"
            threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
        
        if not is_port_available(cfg["host"], cfg["port"]):
            logger.error(f"Port {cfg['port']} already in use!")
            print(color(f" Port {cfg['port']} is busy. Change port in config.json", "red"))
            sys.exit(1)

        success = start_backend_with_retries(cfg)
        if not success:
            logger.error("Backend failed to start.")
            sys.exit(1)

    except Exception as e:
        logger.exception("Fatal launcher error: %s", e)
        print(color("Fatal launcher error. Check log.", "red"))
        sys.exit(1)

if __name__ == "__main__":
    main()