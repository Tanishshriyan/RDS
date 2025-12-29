# backend/behavioral_analyzer.py

import time
import threading
from collections import defaultdict
from typing import Dict

import psutil


class BehavioralAnalyzer:
    """
    STRICT feature extractor for ML-based ransomware detection.
    Produces numeric feature vectors only.
    No scoring. No heuristics. No detection decisions.
    """

    WINDOW_SECONDS = 10  # sliding window for aggregation

    def __init__(self):
        self.total_events = 0
        self.process_windows = {}

        # Per-process counters within time window
        self.process_stats = defaultdict(lambda: {
            "file_writes": 0,
            "file_renames": 0,
            "entropy_values": [],
            "last_seen": time.time()
        })

        self.lock = threading.Lock()

    # -----------------------------
    # EVENT INGESTION
    # -----------------------------
    def ingest_event(self, event: Dict):
        """
        Accepts normalized file/process events from monitor.py
        """

        if not event.get("valid", False):
            return

        pid = event.get("pid")
        if pid is None or pid < 0:
            return

        with self.lock:
            stats = self.process_stats[pid]
            stats["last_seen"] = time.time()

            etype = event.get("event_type")

            if etype == "WRITE":
                stats["file_writes"] += 1
            elif etype == "RENAME":
                stats["file_renames"] += 1

            # Entropy is optional and expensive
            entropy = event.get("entropy")
            if isinstance(entropy, (int, float)):
                stats["entropy_values"].append(entropy)

    # -----------------------------
    # FEATURE EXTRACTION
    # -----------------------------
    def extract_features(self, pid: int) -> Dict:
        """Build ML feature vector - relaxed gates for production"""
        with self.lock:
            stats = self.process_stats.get(pid)
            
            # Relaxed gate: allow processes with NO activity (system processes)
            if not stats:
                stats = {"file_writes": 0, "file_renames": 0, "entropy_values": [], "last_seen": time.time()}
            
            try:
                proc = psutil.Process(pid)
            except psutil.NoSuchProcess:
                return {"valid": False, "reason": "process_not_found"}
            
            # Extract features
            try:
                now = time.time()
                cpu_percent = proc.cpu_percent(interval=None)
                memory_percent = proc.memory_percent()
                threads = proc.num_threads()
                uptime = now - proc.create_time()
                
                try:
                    network_connections = len(proc.net_connections(kind="inet"))
                except:
                    network_connections = 0
                
                entropy_vals = stats.get("entropy_values", [])
                entropy_mean = sum(entropy_vals) / len(entropy_vals) if entropy_vals else 0.0
                
                write_count = stats.get("file_writes", 0)
                rename_count = stats.get("file_renames", 0)
                
                # MATCH train_model.py EXACTLY (22 features)
                features = {
                    "cpu_percent": float(cpu_percent),
                    "memory_percent": float(memory_percent),
                    "threads": int(threads),
                    "uptime": float(uptime),
                    "cpu_spike_count": 0,
                    "file_writes": int(write_count),
                    "file_reads": 0,
                    "file_deletes": 0,
                    "file_renames": int(rename_count),
                    "file_modifications": int(write_count),
                    "extension_changes": 0,
                    "entropy_mean": float(entropy_mean),
                    "entropy_variance": 0.0,
                    "entropy_max": max(entropy_vals) if entropy_vals else 0.0,
                    "high_entropy_file_ratio": 0.0,
                    "rapid_file_ops_count": int(write_count + rename_count) if (write_count + rename_count) > 5 else 0,
                    "mass_file_change_events": 1 if (write_count + rename_count) > 20 else 0,
                    "suspicious_extensions_count": 0,
                    "network_connections": int(network_connections),
                    "outbound_data_kb": 0.0,
                    "read_write_delete_pattern": 0,
                    "process_injection_attempts": 0
                }
                
                # Soft decay for next window
                stats["file_writes"] = int(stats.get("file_writes", 0) * 0.7)
                stats["file_renames"] = int(stats.get("file_renames", 0) * 0.7)
                stats["entropy_values"] = stats.get("entropy_values", [])[-10:]
                stats["last_seen"] = now
                
                return {
                    "valid": True,
                    "pid": pid,
                    "process_name": proc.name(),
                    "features": features
                }
                
            except Exception as e:
                return {"valid": False, "reason": f"feature_extraction_failed: {str(e)}"}

    # -----------------------------
    # MAINTENANCE
    # -----------------------------
    def cleanup(self):
        """
        Remove expired process windows.
        Must NOT hide errors.
        """

        now = time.time()
        with self.lock:
            stale_pids = [
                pid for pid, stats in self.process_stats.items()
                if now - stats["last_seen"] > self.WINDOW_SECONDS * 2
            ]

            for pid in stale_pids:
                del self.process_stats[pid]
    def get_statistics(self):
        return {
            "events_ingested": getattr(self, "total_events", 0),
            "active_pids": len(getattr(self, "process_stats", {})),
            "valid_feature_windows": sum(
                1 for v in getattr(self, "process_stats", {}).values()
                if (time.time() - v.get("last_seen", 0)) <= self.WINDOW_SECONDS
            ),
        }

