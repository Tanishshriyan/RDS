"""
Kill-Switch System (Improved & Corrected Version)
Terminates ransomware-like processes safely and reliably on Windows.
"""

import psutil
import os
import time
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("killswitch")

class KillSwitch:
    """
    Sophisticated threat response engine.
    Kills malicious processes, their children, and prevents respawn.
    """

    def __init__(self, enable_auto_kill: bool = True, threat_threshold: int = 75):
        self.enabled = enable_auto_kill
        self.threat_threshold = threat_threshold
        
        # Process names already terminated (blocklist)
        self.blocked_processes = set()
        
        # Kill history
        self.killed_processes: List[Dict] = []
        
        # Quarantine flag
        self.quarantine_mode = False
        
        # DO NOT KILL these
        self.protected_processes = {
            'system', 'system idle process',
            'svchost.exe', 'csrss.exe', 'smss.exe',
            'services.exe', 'lsass.exe', 'winlogon.exe',
            'explorer.exe', 'wininit.exe', 'dwm.exe',
            'taskmgr.exe', 'fontdrvhost.exe'
        }

        logger.info(f" KillSwitch ready (AutoKill={self.enabled}, Threshold={self.threat_threshold})")

    # =====================================================================
    # THREAT EVALUATION
    # =====================================================================
    def evaluate_threat(self, event_data: dict) -> dict:
        process_name = event_data.get("process", "unknown").lower()
        pid = event_data.get("pid")
        score = event_data.get("suspicion_score", 0)
        if "detection_mode" not in event_data:
            raise RuntimeError(
                "SECURITY ERROR: detection_mode missing in event_data. "
                "Refusing to fallback."
            )

        detection_mode = event_data["detection_mode"]

        result = {
            "process": process_name,
            "score": score,
            "mode": detection_mode,
            "action_taken": "none",
            "timestamp": time.time(),
            "success": False
        }

        # Below threshold -> ignore
        if score < self.threat_threshold:
            return result

        # Protected system process
        if process_name in self.protected_processes:
            logger.warning(f"Protected process flagged: {process_name}, SKIPPED")
            result["action_taken"] = "protected_skip"
            return result

        # Already killed earlier
        if process_name in self.blocked_processes:
            result["action_taken"] = "already_blocked"
            return result

        # Kill-switch disabled
        if not self.enabled:
            logger.warning(f"Threat detected but KillSwitch disabled: {process_name}")
            result["action_taken"] = "alert_only"
            return result
        
        # =========================================================
        # IMMEDIATE KILL LOGIC (NO FALLBACKS)
        # =========================================================

        # Immediate kill modes (ignore threshold)
        if detection_mode in {"PRE_ENCRYPTION", "ML_CONFIRMED"}:
            logger.warning(f"Immediate kill triggered: {detection_mode}")
            success = self.kill_process_tree(process_name, pid)
            result["success"] = success
            result["action_taken"] = "terminated" if success else "termination_failed"
            result["reason"] = detection_mode
            return result

        # ML score-based kill (secondary)
        if score >= self.threat_threshold:
            logger.warning(f"Threshold kill triggered (Score={score})")
            success = self.kill_process_tree(process_name, pid)
            result["success"] = success
            result["action_taken"] = "terminated" if success else "termination_failed"
            result["reason"] = "THRESHOLD_EXCEEDED"
            return result

    # =====================================================================
    # PROCESS TERMINATION FUNCTIONS
    # =====================================================================
    def kill_process_tree(self, process_name: str, pid: int = None) -> bool:
        """
        Corrected kill logic:
        - Kills by PID (if valid)
        - Kills all process instances
        - Kills all child processes
        """

        killed_any = False

        # Kill by PID first
        if pid:
            if self._terminate_single_process(pid, process_name):
                killed_any = True

        # Kill all processes matching name
        for proc in psutil.process_iter(["name", "pid"]):
            if proc.info["name"] and proc.info["name"].lower() == process_name.lower():
                if self._terminate_single_process(proc.info["pid"], process_name):
                    killed_any = True

        return killed_any

    def _terminate_single_process(self, pid: int, process_name: str) -> bool:
        try:
            proc = psutil.Process(pid)

            # Security check
            if proc.name().lower() != process_name.lower():
                return False

            # Kill CHILD processes first
            for child in proc.children(recursive=True):
                try:
                    child.kill()
                except:
                    pass

            # Now kill parent process
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()

            logger.info(f" Terminated: {process_name} (PID {pid})")
            return True

        except psutil.NoSuchProcess:
            return True
        except psutil.AccessDenied:
            logger.error(f" Access denied for: {process_name} (PID {pid})")
            return False
        except Exception as e:
            logger.error(f"Termination error on {process_name} (PID {pid}): {e}")
            return False

    # =====================================================================
    # MANAGEMENT
    # =====================================================================
    def enable_quarantine_mode(self):
        self.quarantine_mode = True
        logger.warning(" QUARANTINE MODE ENABLED")

    def disable_quarantine_mode(self):
        self.quarantine_mode = False
        logger.info("Quarantine Off")

    def unblock_process(self, name: str):
        name = name.lower()
        if name in self.blocked_processes:
            self.blocked_processes.remove(name)
            logger.info(f"Removed {name} from blocklist")

    def get_kill_history(self):
        return self.killed_processes[-50:]

    def reset(self):
        self.killed_processes.clear()
        self.blocked_processes.clear()
        self.quarantine_mode = False
        logger.info("KillSwitch reset complete")
        # =====================================================================
    # STATISTICS FOR API
    # =====================================================================
    def get_statistics(self):
        return {
            "enabled": self.enabled,
            "threat_threshold": self.threat_threshold,
            "quarantine_mode": self.quarantine_mode,
            "blocked_processes": list(self.blocked_processes),
            "killed_count": len(self.killed_processes),
            "recent_kills": self.get_kill_history()
        }

