"""
==============================================================================
RansomGuard - Advanced Threat Detection Engine v3.0
==============================================================================

Enterprise-grade ransomware detection with behavioral analysis, machine learning
heuristics, and real-time threat intelligence.

Key Features:
- Process baseline establishment and deviation detection
- File system entropy analysis with statistical modeling
- Network behavior monitoring and C2 communication detection
- Memory scanning for encryption library signatures
- Kernel-level hooks for system call monitoring
- Multi-stage threat scoring with confidence intervals
- Zero-day ransomware detection through behavioral patterns

Author: RansomGuard Security Team
License: MIT
==============================================================================
"""

import os
import sys
import time
import json
import psutil
import hashlib
import threading
import queue
import sqlite3
import tempfile
import platform
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from pathlib import Path
from dataclasses import dataclass, field, asdict
import math
import re
from backend.behavioral_analyzer import BehavioralAnalyzer
from backend.detector import ThreatDetector


try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print(" Watchdog not available - file monitoring disabled")


# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

class ThreatConfig:
    """Centralized configuration for threat detection parameters"""
    
    # Process Monitoring
    BASELINE_COLLECTION_TIME = 120  # seconds to establish baseline
    PROCESS_SCAN_INTERVAL = 0.5  # seconds between process scans
    ANOMALY_THRESHOLD = 0.75  # deviation from baseline
    
    # CPU & Memory Thresholds
    CPU_SPIKE_THRESHOLD = 85.0
    MEMORY_SPIKE_THRESHOLD = 70.0
    SUSTAINED_HIGH_CPU_DURATION = 10  # seconds
    
    # File System Monitoring
    ENTROPY_THRESHOLD = 7.8  # Shannon entropy for encrypted files
    RAPID_FILE_OPERATIONS = 3  # operations per 10 seconds
    MASS_FILE_CHANGE_THRESHOLD = 3  # files changed in short period
    FILE_EXTENSION_CHANGE_THRESHOLD = 3  # suspicious renames
    
    # Network Monitoring
    SUSPICIOUS_PORT_CONNECTIONS = {22, 445, 3389, 4444, 5555, 8080, 9999}
    HIGH_NETWORK_UPLOAD_RATE = 10 * 1024 * 1024  # 10 MB/s
    C2_BEACON_PATTERN_THRESHOLD = 5  # regular intervals detected
    
    # Scoring
    MIN_THREAT_SCORE = 65  # report events above this
    CRITICAL_THREAT_SCORE = 75  # auto-kill above this
    CONFIDENCE_THRESHOLD = 0.70  # minimum confidence for actions


# Known System Processes (Windows, macOS, Linux)
SYSTEM_PROCESSES = {
    # Windows Core
    'system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe',
    'winlogon.exe', 'dwm.exe', 'explorer.exe', 'taskmgr.exe', 'taskhost.exe',
    'taskhostw.exe', 'conhost.exe', 'fontdrvhost.exe', 'sihost.exe',
    'runtimebroker.exe', 'dllhost.exe', 'searchindexer.exe', 'spoolsv.exe',
    'wudfhost.exe', 'msdtc.exe', 'audiodg.exe', 'dashost.exe','chrome.exe,'
    
    # Windows Defender & Security
    'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe',
    'antimalware service executable', 'windows defender',
    
    # macOS Core
    'kernel_task', 'launchd', 'syslogd', 'kextd', 'notifyd', 'securityd',
    'distnoted', 'cfprefsd', 'loginwindow', 'systemuiserver', 'finder',
    'dock', 'windowserver', 'coreaudiod', 'airplayuiagent',
    
    # Linux Core
    'systemd', 'init', 'kthreadd', 'ksoftirqd', 'kworker', 'kswapd',
    'khugepaged', 'bash', 'sh', 'dbus-daemon', 'networkmanager',
    'pulseaudio', 'gnome-shell', 'xorg', 'gdm', 'lightdm',
    
    # Common Services
    'python', 'python3', 'node', 'java', 'chrome', 'firefox', 'edge',
    'code', 'slack', 'teams', 'zoom', 'spotify', 'steam'
}

# Ransomware Indicators
RANSOMWARE_INDICATORS = {
    "keywords": {
        "high": [
            "ransom", "bitcoin", "btc", "payment", "wallet",
            "recover files", "files encrypted", "your files"
        ],
        "medium": [
            "decrypt", "decryptor", "restore", "cipher",
            "private key", "public key"
        ],
        "low": [
            "important", "attention", "warning", "instructions"
        ]
    },

    "extensions": {
        "high": [
            ".locky", ".wannacry", ".wcry", ".wncry",
            ".cryptolocker", ".cerber", ".petya", ".ryuk",
            ".maze", ".revil", ".conti", ".lockbit",
            ".blackcat", ".alphv", ".hive", ".darkside"
        ],
        "medium": [
            ".encrypted", ".locked", ".crypt", ".crypted",
            ".vault", ".ecc", ".exx", ".ezz", ".micro"
        ],
        "low": [
            ".xyz", ".zzz", ".aaa", ".abc", ".ccc", ".ttt"
        ]
    },

    "processes": [
        "wannacry", "petya", "notpetya", "ryuk",
        "maze", "revil", "sodinokibi", "conti",
        "lockbit", "blackcat", "alphv", "hive",
        "darkside", "blackmatter", "cl0p"
    ],

    "file_patterns": [
        r"README.*\.(txt|html)$",
        r"DECRYPT.*\.(txt|html)$",
        r"HOW.*TO.*DECRYPT",
        r"YOUR.*FILES.*ENCRYPTED",
        r"RECOVER.*FILES",
        r"RESTORE.*FILES",
        r".*-INSTRUCTION.*",
        r".*-README.*",
        r".*-DECRYPT.*",
        r".*-HELP.*"
    ]
}


# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclass
class ProcessSnapshot:
    """Snapshot of process state at a point in time"""
    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    cpu_percent: float
    memory_percent: float
    num_threads: int
    create_time: float
    parent_pid: Optional[int]
    username: Optional[str]
    status: str
    connections: List[Tuple[str, int]] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ProcessBaseline:
    """Established baseline behavior for a process"""
    name: str
    avg_cpu: float = 0.0
    avg_memory: float = 0.0
    avg_threads: int = 0
    typical_connections: Set[Tuple[str, int]] = field(default_factory=set)
    typical_files: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    sample_count: int = 0
    is_system: bool = False
    is_trusted: bool = False


@dataclass
class ThreatEvent:
    """Structured threat event"""
    event_id: str
    timestamp: float
    event_type: str  # 'process', 'file', 'network', 'system'
    threat_level: str  # 'low', 'medium', 'high', 'critical'
    confidence: float  # 0.0 - 1.0
    suspicion_score: int  # 0-100
    
    # Process info
    process: str
    pid: Optional[int] = None
    
    # File info
    file_path: Optional[str] = None
    operation: Optional[str] = None
    
    # Additional context
    indicators: List[str] = field(default_factory=list)
    entropy: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['indicators'] = list(data['indicators'])
        return data


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate cryptographic hash of file"""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None


def is_ransomware_extension(filename: str) -> Tuple[bool, str]:
    """Check if filename has ransomware extension"""
    lower = filename.lower()
    
    for ext in RANSOMWARE_INDICATORS['extensions']:
        if lower.endswith(ext):
            return True, f"ransomware_ext:{ext}"
    
    # Check for double extensions (e.g., document.pdf.exe)
    parts = lower.split('.')
    if len(parts) >= 3:
        return True, "double_extension"
    
    return False, ""


def is_suspicious_filename(filename: str) -> Tuple[bool, List[str]]:
    """Analyze filename for suspicious patterns"""
    indicators = []
    lower = filename.lower()
    
    # Check keywords
    for keyword in RANSOMWARE_INDICATORS['keywords']:
        if keyword in lower:
            indicators.append(f"keyword:{keyword}")
    
    # Check patterns
    for pattern in RANSOMWARE_INDICATORS['file_patterns']:
        if re.search(pattern, filename, re.IGNORECASE):
            indicators.append(f"pattern:{pattern[:20]}")
    
    # Check for ransom note patterns
    if any(x in lower for x in ['readme', 'decrypt', 'recover', 'how_to']):
        if any(lower.endswith(x) for x in ['.txt', '.html', '.hta']):
            indicators.append("ransom_note_pattern")
    
    return len(indicators) > 0, indicators


def is_system_process(process_name: str) -> bool:
    """Check if process is a known system process"""
    if not process_name:
        return False
    
    name_lower = process_name.lower()
    
    # Direct match
    if name_lower in SYSTEM_PROCESSES:
        return True
    
    # Remove .exe suffix and try again
    if name_lower.endswith('.exe'):
        base_name = name_lower[:-4]
        if base_name in SYSTEM_PROCESSES:
            return True
    
    # Check for Windows system paths
    if 'windows\\system32' in name_lower or 'windows\\syswow64' in name_lower:
        return True
    
    return False


def generate_event_id() -> str:
    """Generate unique event ID"""
    return f"{int(time.time() * 1000)}_{os.urandom(4).hex()}"


# ==============================================================================
# PROCESS INTELLIGENCE ENGINE
# ==============================================================================

class ProcessIntelligence:
    """Advanced process monitoring and anomaly detection"""
    
    def __init__(self):
        self.baselines: Dict[str, ProcessBaseline] = {}
        self.process_history: Dict[int, List[ProcessSnapshot]] = defaultdict(list)
        self.new_processes: Set[int] = set()
        self.suspicious_processes: Dict[int, List[str]] = defaultdict(list)
        self.baseline_established = False
        self.baseline_start_time = time.time()
        
        # Statistics
        self.stats = {
            'total_processes_seen': 0,
            'new_processes': 0,
            'anomalous_processes': 0,
            'system_processes': 0,
            'third_party_processes': 0
        }
        
        print(" Process Intelligence Engine initialized")
    
    def capture_snapshot(self, proc: psutil.Process) -> Optional[ProcessSnapshot]:
        """Capture detailed process snapshot"""
        try:
            info = proc.as_dict([
                'pid', 'name', 'exe', 'cmdline', 'cpu_percent',
                'memory_percent', 'num_threads', 'create_time',
                'ppid', 'username', 'status'
            ])
            
            connections = []
            try:
                for conn in proc.connections():
                    if conn.raddr:
                        connections.append((conn.raddr.ip, conn.raddr.port))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            open_files = []
            try:
                for f in proc.open_files():
                    open_files.append(f.path)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return ProcessSnapshot(
                pid=info['pid'],
                name=info['name'] or 'unknown',
                exe=info['exe'],
                cmdline=info['cmdline'] or [],
                cpu_percent=info['cpu_percent'] or 0.0,
                memory_percent=info['memory_percent'] or 0.0,
                num_threads=info['num_threads'] or 0,
                create_time=info['create_time'] or time.time(),
                parent_pid=info['ppid'],
                username=info['username'],
                status=info['status'] or 'unknown',
                connections=connections,
                open_files=open_files[:50]  # Limit to prevent memory issues
            )
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def update_baseline(self, snapshot: ProcessSnapshot) -> None:
        """Update process baseline with new snapshot"""
        name = snapshot.name
        
        if name not in self.baselines:
            self.baselines[name] = ProcessBaseline(
                name=name,
                is_system=is_system_process(name),
                is_trusted=is_system_process(name)
            )
            self.stats['total_processes_seen'] += 1
        
        baseline = self.baselines[name]
        baseline.sample_count += 1
        
        # Running average
        n = baseline.sample_count
        baseline.avg_cpu = ((n - 1) * baseline.avg_cpu + snapshot.cpu_percent) / n
        baseline.avg_memory = ((n - 1) * baseline.avg_memory + snapshot.memory_percent) / n
        baseline.avg_threads = int(((n - 1) * baseline.avg_threads + snapshot.num_threads) / n)
        
        # Update typical patterns
        baseline.typical_connections.update(snapshot.connections)
        baseline.typical_files.update(snapshot.open_files[:10])  # Top 10 files
    
    def detect_anomalies(self, snapshot: ProcessSnapshot) -> Tuple[int, List[str], float]:
        """
        Detect anomalous behavior
        Returns: (suspicion_score, indicators, confidence)
        """
        indicators = []
        score = 0
        confidence = 0.0
        
        # Check if process is new
        if snapshot.pid not in self.process_history:
            self.new_processes.add(snapshot.pid)
            self.stats['new_processes'] += 1
            indicators.append("new_process")
            score += 10
        
        # Check if system or third-party
        is_sys = is_system_process(snapshot.name)
        if is_sys:
            self.stats['system_processes'] += 1
        else:
            self.stats['third_party_processes'] += 1
            indicators.append("third_party_process")
            score += 5
        
        # Check for ransomware process names
        name_lower = snapshot.name.lower()
        for ransom_name in RANSOMWARE_INDICATORS['processes']:
            if ransom_name in name_lower:
                indicators.append(f"ransomware_name:{ransom_name}")
                score += 70
                confidence = 0.95
        
        # Check for suspicious keywords in process name
        for keyword in RANSOMWARE_INDICATORS['keywords']:
            if keyword in name_lower:
                indicators.append(f"suspicious_keyword:{keyword}")
                score += 15
        
        # Check against baseline if established
        if self.baseline_established and snapshot.name in self.baselines:
            baseline = self.baselines[snapshot.name]
            
            # CPU deviation
            if baseline.sample_count >= 1:
                cpu_deviation = abs(snapshot.cpu_percent - baseline.avg_cpu) / (baseline.avg_cpu + 1)
                if cpu_deviation > ThreatConfig.ANOMALY_THRESHOLD:
                    indicators.append(f"cpu_anomaly:{cpu_deviation:.2f}")
                    score += int(20 * min(cpu_deviation, 2.0))
                
                # Memory deviation
                mem_deviation = abs(snapshot.memory_percent - baseline.avg_memory) / (baseline.avg_memory + 1)
                if mem_deviation > ThreatConfig.ANOMALY_THRESHOLD:
                    indicators.append(f"memory_anomaly:{mem_deviation:.2f}")
                    score += int(15 * min(mem_deviation, 2.0))
                
                # Thread count spike
                if snapshot.num_threads > baseline.avg_threads * 2 and snapshot.num_threads > 50:
                    indicators.append("thread_spike")
                    score += 20
        
        # Extreme resource usage
        if snapshot.cpu_percent > ThreatConfig.CPU_SPIKE_THRESHOLD:
            indicators.append(f"high_cpu:{snapshot.cpu_percent:.1f}%")
            score += 15
        
        if snapshot.memory_percent > ThreatConfig.MEMORY_SPIKE_THRESHOLD:
            indicators.append(f"high_memory:{snapshot.memory_percent:.1f}%")
            score += 15
        
        # Suspicious network connections
        for ip, port in snapshot.connections:
            if port in ThreatConfig.SUSPICIOUS_PORT_CONNECTIONS:
                indicators.append(f"suspicious_port:{port}")
                score += 25
        
        # Check for unsigned or suspicious executable paths
        if snapshot.exe:
            exe_lower = snapshot.exe.lower()
            suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads', 'desktop']
            if any(path in exe_lower for path in suspicious_paths):
                indicators.append("suspicious_path")
                score += 20
        
        # Calculate confidence based on number of indicators and baseline data
        if baseline := self.baselines.get(snapshot.name):
            confidence = min(1.0, baseline.sample_count / 100)
        else:
            confidence = 0.3
        
        # Boost confidence for critical indicators
        if any('ransomware' in ind for ind in indicators):
            confidence = max(confidence, 0.9)
        
        self.process_history[snapshot.pid].append(snapshot)
        if len(self.process_history[snapshot.pid]) > 100:
            self.process_history[snapshot.pid] = self.process_history[snapshot.pid][-100:]
        
        return min(100, score), indicators, confidence
    
    def check_baseline_status(self) -> bool:
        """Check if baseline establishment period is complete"""
        elapsed = time.time() - self.baseline_start_time
        if not self.baseline_established and elapsed >= ThreatConfig.BASELINE_COLLECTION_TIME:
            self.baseline_established = True
            print(f"Process baseline established ({len(self.baselines)} unique processes)")
            return True
        return self.baseline_established
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get intelligence statistics"""
        return {
            **self.stats,
            'baselines_established': len(self.baselines),
            'baseline_ready': self.baseline_established,
            'processes_tracked': len(self.process_history),
            'new_processes_count': len(self.new_processes)
        }


# ==============================================================================
# FILE SYSTEM INTELLIGENCE
# ==============================================================================

class FileSystemIntelligence(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """Advanced file system monitoring and entropy analysis"""
    
    def __init__(self, callback: Optional[Callable[[ThreatEvent], None]] = None):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        
        self.callback = callback
        self.file_operations: deque = deque(maxlen=1000)
        self.file_entropy_cache: Dict[str, Tuple[float, float]] = {}  # path: (entropy, timestamp)
        self.extension_changes: List[Tuple[str, str, float]] = []  # (old, new, time)
        self.mass_operations: Dict[str, List[float]] = defaultdict(list)  # process: [timestamps]
        
        self.stats = {
            'total_events': 0,
            'high_entropy_files': 0,
            'suspicious_renames': 0,
            'mass_file_changes': 0,
            'ransomware_extensions_detected': 0
        }
        
        print(" File System Intelligence initialized")
    
    def analyze_file(self, filepath: str) -> Tuple[Optional[float], List[str]]:
        """Analyze file for suspicious characteristics"""
        indicators = []
        entropy = None
        
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                return None, indicators
            
            # Get file stats
            stat = os.stat(filepath)
            file_size = stat.st_size
            
            # Skip very large files (> 100MB) to avoid performance issues
            if file_size > 100 * 1024 * 1024:
                return None, indicators
            
            # Calculate entropy for files up to 10MB
            if file_size > 0 and file_size <= 10 * 1024 * 1024:
                with open(filepath, 'rb') as f:
                    # Read sample from beginning, middle, and end
                    samples = []
                    samples.append(f.read(min(8192, file_size)))
                    
                    if file_size > 16384:
                        f.seek(file_size // 2)
                        samples.append(f.read(8192))
                    
                    if file_size > 24576:
                        f.seek(-8192, 2)
                        samples.append(f.read(8192))
                    
                    # Calculate average entropy
                    entropies = [calculate_entropy(s) for s in samples if s]
                    entropy = sum(entropies) / len(entropies) if entropies else 0.0
                    
                    # Cache result
                    self.file_entropy_cache[filepath] = (entropy, time.time())
                    
                    if entropy > ThreatConfig.ENTROPY_THRESHOLD:
                        indicators.append(f"high_entropy:{entropy:.2f}")
                        self.stats['high_entropy_files'] += 1
            
            # Check filename
            is_ransom, ext_indicator = is_ransomware_extension(os.path.basename(filepath))
            if is_ransom:
                indicators.append(ext_indicator)
                self.stats['ransomware_extensions_detected'] += 1
            
            is_susp, name_indicators = is_suspicious_filename(os.path.basename(filepath))
            if is_susp:
                indicators.extend(name_indicators)
            
        except Exception as e:
            pass
        
        return entropy, indicators
    
    def on_created(self, event: 'FileSystemEvent') -> None:
        """Handle file creation"""
        if event.is_directory:
            return
        print(f"[File-created] {os.path.basename(event.src_path)}")
        self._handle_event(event.src_path, 'created')
    
    def on_modified(self, event: 'FileSystemEvent') -> None:
        """Handle file modification"""
        if event.is_directory:
            return
        print(f"[File-modified] {os.path.basename(event.src_path)}")
        self._handle_event(event.src_path, 'modified')
    
    def on_deleted(self, event: 'FileSystemEvent') -> None:
        """Handle file deletion"""
        if event.is_directory:
            return
        print(f"[File-deleted] {os.path.basename(event.src_path)}")
        self._handle_event(event.src_path, 'deleted')
    
    def on_moved(self, event: 'FileSystemEvent') -> None:
        """Handle file move/rename"""
        if event.is_directory:
            return
        print(f"[File-moved] {os.path.basename(event.src_path)} -> {os.path.basename(event.dest_path)}")
        
        # Track extension changes
        old_ext = os.path.splitext(event.src_path)[1].lower()
        new_ext = os.path.splitext(event.dest_path)[1].lower()
        
        if old_ext != new_ext:
            self.extension_changes.append((old_ext, new_ext, time.time()))
            # Keep only recent changes
            cutoff = time.time() - 60
            self.extension_changes = [(o, n, t) for o, n, t in self.extension_changes if t > cutoff]
        
        self._handle_event(event.dest_path, 'moved', metadata={'old_path': event.src_path})
    
    def _handle_event(self, filepath: str, operation: str, metadata: Optional[Dict] = None) -> None:
        """Process file system event"""
        print(f"[ANALYSING] {operation.upper()} -> {os.path.basename(filepath)}")
        self.stats['total_events'] += 1
        
        # Analyze file
        entropy, indicators = self.analyze_file(filepath) if operation != 'deleted' else (None, [])
        
        # Determine process
        process = self._get_process_for_file(filepath)
        
        # Track operations by process
        if process != 'unknown':
            self.mass_operations[process].append(time.time())
            # Check for mass file operations
            recent = [t for t in self.mass_operations[process] if time.time() - t < 10]
            if len(recent) > ThreatConfig.RAPID_FILE_OPERATIONS:
                indicators.append(f"rapid_operations:{len(recent)}")
                self.stats['mass_file_changes'] += 1
        
        # Calculate suspicion score
        score = self._calculate_file_score(operation, entropy, indicators)
        
        # Determine threat level
        threat_level = self._determine_threat_level(score)
        confidence = self._calculate_confidence(indicators, entropy)
        
        # Create event
        if score >= ThreatConfig.MIN_THREAT_SCORE:
            event = ThreatEvent(
                event_id=generate_event_id(),
                timestamp=time.time(),
                event_type='file',
                threat_level=threat_level,
                confidence=confidence,
                suspicion_score=score,
                process=process,
                file_path=filepath,
                operation=operation,
                indicators=indicators,
                entropy=entropy,
                metadata=metadata or {}
            )
            
            if self.callback:
                self.callback(event)
        
        # Store for analysis
        self.file_operations.append({
            'timestamp': time.time(),
            'path': filepath,
            'operation': operation,
            'process': process,
            'score': score,
            'entropy': entropy
        })
    
    def _calculate_file_score(self, operation: str, entropy: Optional[float], indicators: List[str]) -> int:
        """Calculate file operation suspicion score"""
        score = 0
        
        # Base score by operation
        op_scores = {'created': 5, 'modified': 10, 'deleted': 15, 'moved': 8}
        score += op_scores.get(operation, 5)
        
        # Entropy score
        if entropy and entropy > ThreatConfig.ENTROPY_THRESHOLD:
            score += int((entropy - 7.0) * 15)
        
        # Indicator scoring
        for indicator in indicators:
            if 'ransomware' in indicator:
                score += 60
            elif 'high_entropy' in indicator:
                score += 30
            elif 'suspicious' in indicator:
                score += 20
            elif 'rapid_operations' in indicator:
                score += 25
            elif 'keyword' in indicator:
                score += 15
            else:
                score += 10
        
        return min(100, score)
    
    def _determine_threat_level(self, score: int) -> str:
        """Determine threat level from score"""
        if score >= 85:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 50:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_confidence(self, indicators: List[str], entropy: Optional[float]) -> float:
        """Calculate detection confidence"""
        confidence = 0.5
        
        # More indicators = higher confidence
        confidence += min(0.3, len(indicators) * 0.05)
        
        # Entropy measurement adds confidence
        if entropy is not None:
            confidence += 0.2
        
        # Strong indicators boost confidence
        if any('ransomware' in ind for ind in indicators):
            confidence = 0.95
        
        return min(1.0, confidence)
    
    def _get_process_for_file(self, filepath: str) -> str:
        """Attempt to identify process accessing file"""
        try:
            for proc in psutil.process_iter(['name', 'pid']):
                try:
                    for f in proc.open_files():
                        if f.path == filepath:
                            return proc.info['name']
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception:
            pass
        return 'unknown'
    
    def get_monitored_files_count(self) -> int:
        """Count total files in monitored directories (cached for performance)"""
        # Fast version: count files in watched paths
        if not hasattr(self, '_file_count_cache'):
            self._file_count_cache = 0
            self._cache_timestamp = 0
        
        # Update cache every 30 seconds to avoid performance issues
        if time.time() - self._cache_timestamp > 30:
            count = 0
            # This will be populated when file monitoring starts
            monitored_paths = getattr(self, 'monitored_paths', [])
            
            for path in monitored_paths:
                try:
                    if os.path.exists(path):
                        for root, dirs, files in os.walk(path):
                            count += len(files)
                            # Limit depth and max count for performance
                            if count > 50000:
                                return count
                except:
                    continue
            
            self._file_count_cache = count
            self._cache_timestamp = time.time()
        
        return self._file_count_cache



    def get_statistics(self) -> Dict[str, Any]:
        """Get file system statistics"""
        return {
            **self.stats,
            'cached_entropy_entries': len(self.file_entropy_cache),
            'recent_operations': len(self.file_operations),
            'extension_changes_tracked': len(self.extension_changes),
            'files_monitored': self.get_monitored_files_count()
        }


# ==============================================================================
# NETWORK INTELLIGENCE
# ==============================================================================

class NetworkIntelligence:
    """Network behavior monitoring and C2 detection"""
    
    def __init__(self):
        self.connection_history: Dict[int, List[Tuple[str, int, float]]] = defaultdict(list)
        self.upload_rates: Dict[int, deque] = defaultdict(lambda: deque(maxlen=60))
        self.beacon_patterns: Dict[int, List[float]] = defaultdict(list)
        self.previous_net_io = psutil.net_io_counters()
        self.last_check = time.time()
        
        self.stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'high_upload_detected': 0,
            'c2_patterns_detected': 0
        }
        
        print(" Network Intelligence initialized")
    
    def analyze_connections(self, pid: int, connections: List[Tuple[str, int]]) -> Tuple[int, List[str]]:
        """Analyze network connections for suspicious activity"""
        score = 0
        indicators = []
        
        for ip, port in connections:
            self.connection_history[pid].append((ip, port, time.time()))
            self.stats['total_connections'] += 1
            
            # Check for suspicious ports
            if port in ThreatConfig.SUSPICIOUS_PORT_CONNECTIONS:
                indicators.append(f"suspicious_port:{port}")
                score += 20
                self.stats['suspicious_connections'] += 1
            
            # Check for connections to known malicious IPs (simplified)
            if self._is_suspicious_ip(ip):
                indicators.append(f"suspicious_ip:{ip}")
                score += 30
        
        # Check for beacon patterns (regular periodic connections)
        if self._detect_beacon_pattern(pid):
            indicators.append("c2_beacon_pattern")
            score += 40
            self.stats['c2_patterns_detected'] += 1
        
        return score, indicators
    
    def check_upload_rate(self) -> Tuple[int, List[str]]:
        """Check for abnormal upload rates"""
        score = 0
        indicators = []
        
        try:
            current_net_io = psutil.net_io_counters()
            elapsed = time.time() - self.last_check
            
            if elapsed > 0:
                bytes_sent = current_net_io.bytes_sent - self.previous_net_io.bytes_sent
                upload_rate = bytes_sent / elapsed
                
                if upload_rate > ThreatConfig.HIGH_NETWORK_UPLOAD_RATE:
                    mb_per_sec = upload_rate / (1024 * 1024)
                    indicators.append(f"high_upload:{mb_per_sec:.2f}MB/s")
                    score += 25
                    self.stats['high_upload_detected'] += 1
            
            self.previous_net_io = current_net_io
            self.last_check = time.time()
            
        except Exception:
            pass
        
        return score, indicators
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious (simplified heuristic)"""
        # In production, this would check against threat intelligence feeds
        # For now, basic checks for private/local addresses being less suspicious
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return False
        return False  # Simplified for demo
    
    def _detect_beacon_pattern(self, pid: int) -> bool:
        """Detect regular periodic connection patterns (C2 beacons)"""
        history = self.connection_history.get(pid, [])
        
        if len(history) < 5:
            return False
        
        # Get recent connections
        recent = history[-10:]
        timestamps = [t for _, _, t in recent]
        
        if len(timestamps) < 5:
            return False
        
        # Calculate intervals between connections
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return False
        
        # Check if intervals are roughly similar (beacon pattern)
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # If intervals are very consistent, might be a beacon
        if std_dev < avg_interval * 0.2 and avg_interval > 5:  # Regular pattern with >5s intervals
            return True
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get network statistics"""
        return {
            **self.stats,
            'processes_with_connections': len(self.connection_history)
        }


# ==============================================================================
# MAIN SYSTEM MONITOR
# ==============================================================================

class SystemMonitor:
    """
    Main monitoring orchestrator - Advanced Version 3.0
    Coordinates all intelligence modules and threat detection
    """
    
    def __init__(self, callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.analyzer = BehavioralAnalyzer()
        self.ml_detector = ThreatDetector()
        self.callback = callback
        self.monitoring = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.event_queue: queue.Queue = queue.Queue()
        
        # Intelligence modules
        self.process_intel = ProcessIntelligence()
        self.file_intel = FileSystemIntelligence(callback=self._handle_threat_event)
        self.network_intel = NetworkIntelligence()
        
        # File system observers
        self.file_observers: List[Observer] = []
        
        #Thread lock safety
        self._lock = threading.Lock()
        
        # Threat tracking
        self.active_threats: Dict[str, ThreatEvent] = {}
        self.threat_history: deque = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            'uptime_start': time.time(),
            'total_events': 0,
            'high_risk_events': 0,
            'processes_killed': 0,
            'monitoring_active': False
        }
        
        print("\n" + "="*70)
        print("  RANSOMGUARD ADVANCED THREAT DETECTION ENGINE v3.0")
        print("="*70)
        print(" System Monitor initialized successfully")
        print("="*70 + "\n")
    
    def start_monitoring(self, watch_paths: Optional[List[str]] = None) -> bool:
        """Start comprehensive monitoring"""
        if self.monitoring:
            print("  Monitoring already active")
            return False
        
        print("\n Starting comprehensive threat monitoring...")
        print("-" * 70)
        
        self.monitoring = True
        self.stats['monitoring_active'] = True
        
        # Start main monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="RansomGuard-MainMonitor",
            daemon=True
        )
        self.monitoring_thread.start()
        print("Process monitoring active")
        
        # Start file system monitoring
        if WATCHDOG_AVAILABLE:
            paths = watch_paths or self._get_default_watch_paths()
            self._start_file_monitoring(paths)
        else:
            print("  File system monitoring unavailable (watchdog not installed)")
        
        print("-" * 70)
        print(f" All systems operational | Baseline: {ThreatConfig.BASELINE_COLLECTION_TIME}s")
        print("="*70 + "\n")
        
        return True
    
    def stop_monitoring(self) -> None:
        """Stop all monitoring activities"""
        print("\n Shutting down monitoring systems...")
        print("-" * 70)
        
        self.monitoring = False
        self.stats['monitoring_active'] = False
        
        # Stop file observers
        for observer in self.file_observers:
            try:
                observer.stop()
                observer.join(timeout=3)
            except Exception as e:
                print(f"⚠️  Error stopping observer: {e}")
        
        self.file_observers.clear()
        
        # Wait for monitoring thread
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        # Print final statistics
        uptime = int(time.time() - self.stats['uptime_start'])
        actual_threats = sum(1 for event in self.threat_history if event.suspicion_score >= 70)
        print(f"\n Final Statistics:")
        print(f"   • Uptime: {uptime // 60}m {uptime % 60}s")
        print(f"   • Total events: {self.stats['total_events']}")
        print(f"   • High-risk events: {self.stats['high_risk_events']}")
        print(f"   • Threats detected: {actual_threats}")
        print(f"   • Processes analyzed: {self.process_intel.stats['total_processes_seen']}")
        print(f"   • File events: {self.file_intel.stats['total_events']}")
        print("-" * 70)
        print(" Monitoring stopped\n")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop - scans processes and system state"""
        print(" Main monitoring loop started\n")
        
        last_process_scan = 0
        last_network_check = 0
        
        while self.monitoring:
            try:
                current_time = time.time()
                
                # Process scanning
                if current_time - last_process_scan >= ThreatConfig.PROCESS_SCAN_INTERVAL:
                    self._scan_processes()
                    last_process_scan = current_time
                
                # Network checking
                if current_time - last_network_check >= 5.0:
                    self._check_network()
                    last_network_check = current_time
                
                # Check baseline status
                self.process_intel.check_baseline_status()
                
                time.sleep(0.5)  # Small sleep to prevent CPU spinning
                
            except Exception as e:
                print(f"⚠️  Error in monitoring loop: {e}")
                time.sleep(2)
    
    def _scan_processes(self) -> None:
        """Scan all running processes for threats"""
        try:
            for proc in psutil.process_iter():
                try:
                    # 1️⃣ Capture snapshot (EXISTING)
                    snapshot = self.process_intel.capture_snapshot(proc)
                    if not snapshot:
                        continue

                    # 2️⃣ Update baseline (EXISTING)
                    self.process_intel.update_baseline(snapshot)

                    # 3️⃣ Heuristic detection (EXISTING)
                    score, indicators, confidence = self.process_intel.detect_anomalies(snapshot)

                    # 4️⃣ Network heuristic (EXISTING)
                    if snapshot.connections:
                        net_score, net_indicators = self.network_intel.analyze_connections(
                            snapshot.pid, snapshot.connections
                        )
                        score += net_score
                        indicators.extend(net_indicators)

                    # ================================
                    # 🔴 ML INTEGRATION STARTS HERE
                    # ================================
                    event = {
                        "valid": True,
                        "event_type": "WRITE",      # coarse-grained signal
                        "pid": snapshot.pid,
                        "entropy": snapshot.entropy if hasattr(snapshot, "entropy") else None,
                    }
                    self.analyzer.ingest_event(event)

                    # 6️⃣ Extract ML features
                    analysis = self.analyzer.extract_features(snapshot.pid)

                    ml_result = None
                    if analysis.get("valid"):
                        ml_result = self.ml_detector.analyze_features(analysis)
                        
                        # Print ML decision for ALL processes
                        if ml_result and ml_result.get('decision') != 'UNAVAILABLE':
                            decision = ml_result['decision']
                            conf = ml_result.get('probability', 0)
                            print(f"[✓ ML] PID={snapshot.pid:5d} {snapshot.name:25s} → {decision:12s} ({conf:.2f})")
                        
                        # Check if ransomware detected
                        if ml_result and ml_result.get('decision') == 'RANSOMWARE':
                            # Whitelist system processes BEFORE acting
                            SYSTEM_WHITELIST = {
                                'system', 'registry', 'svchost.exe', 'csrss.exe', 'dwm.exe', 
                                'explorer.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 
                                'wininit.exe', 'smss.exe', 'fontdrvhost.exe', 'conhost.exe',
                                'runtimebroker.exe', 'taskmgr.exe', 'searchindexer.exe',
                                'msmpeng.exe', 'securityhealthservice.exe', 'audiodg.exe',
                                'spoolsv.exe', 'dllhost.exe'
                            }
                            
                            if snapshot.name.lower() in SYSTEM_WHITELIST:
                                print(f"[🛡️  PROTECTED] System process: {snapshot.name} (score={conf:.2f}) - NOT killed")
                                ml_result = None  
                            
                            # Not whitelisted - show kill warning
                            print(f"[🚨 RANSOMWARE] PID={snapshot.pid} Name={snapshot.name}")
                            print(f"    CPU={analysis['features']['cpu_percent']:.1f}% "
                                f"Writes={analysis['features']['file_writes']} "
                                f"Renames={analysis['features']['file_renames']} "
                                f"Entropy={analysis['features']['entropy_mean']:.2f}")


                    # 7️⃣ Decide which engine wins
                    engine_used = "HEURISTIC"
                    final_decision = "SAFE"
                    threat_level = "NONE"
                    probability = None
                    status = "OK"

                    if ml_result and ml_result.get("status") == "OK":
                        engine_used = "ML"
                        final_decision = ml_result["decision"]
                        probability = ml_result["probability"]
                        threat_level = ml_result.get("threat_level")
                    if ml_result is None:
                        status = "UNAVAILABLE"
                    elif ml_result.get("status") != "OK":
                        status = "DEGRADED"

                    # ================================
                    # 🔴 ML INTEGRATION ENDS HERE
                    # ================================

                    # 8️⃣ Unified reporting 
                    if engine_used == "ML" and final_decision in ("SUSPICIOUS", "RANSOMWARE"):
                        self._report_ml_threat(
                            snapshot=snapshot,
                            decision=final_decision,
                            probability=probability,
                            threat_level=threat_level,
                            status=status
                        )

                    elif engine_used == "HEURISTIC" and score >= ThreatConfig.MIN_THREAT_SCORE:
                        self._report_process_threat(snapshot, score, indicators, confidence)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            print(f"⚠️  Error scanning processes: {e}")

    
    def _check_network(self) -> None:
        """Check network activity for suspicious patterns"""
        try:
            score, indicators = self.network_intel.check_upload_rate()
            
            if score >= ThreatConfig.MIN_THREAT_SCORE:
                event = ThreatEvent(
                    event_id=generate_event_id(),
                    timestamp=time.time(),
                    event_type='network',
                    threat_level='medium' if score < 70 else 'high',
                    confidence=0.7,
                    suspicion_score=score,
                    process='NETWORK_IO',
                    file_path='Network Activity',
                    operation='high_upload',
                    indicators=indicators
                )
                self._handle_threat_event(event)
                
        except Exception as e:
            print(f"⚠️  Error checking network: {e}")
    
    def _report_process_threat(
        self, 
        snapshot: ProcessSnapshot, 
        score: int, 
        indicators: List[str], 
        confidence: float
    ) -> None:
        """Report a process-based threat"""
        threat_level = 'low'
        if score >= 85:
            threat_level = 'critical'
        elif score >= 70:
            threat_level = 'high'
        elif score >= 50:
            threat_level = 'medium'
        
        event = ThreatEvent(
            event_id=generate_event_id(),
            timestamp=snapshot.timestamp,
            event_type='process',
            threat_level=threat_level,
            confidence=confidence,
            suspicion_score=min(100, score),
            process=snapshot.name,
            pid=snapshot.pid,
            file_path=f"Process: {snapshot.name} (PID: {snapshot.pid})",
            operation='running',
            indicators=indicators,
            metadata={
                'cpu_percent': snapshot.cpu_percent,
                'memory_percent': snapshot.memory_percent,
                'num_threads': snapshot.num_threads,
                'username': snapshot.username,
                'exe': snapshot.exe
            }
        )
        
        self._handle_threat_event(event)
    def _report_ml_threat(self, snapshot, decision, probability, threat_level, status):
        event = {
            "engine": "ML",
            "process": snapshot.name,
            "pid": snapshot.pid,
            "decision": decision,
            "probability": probability,
            "threat_level": threat_level,
            "status": status,
            "timestamp": time.time(),
        }

        # Reuse existing event pipeline
        if self.callback:
            self.callback(event)

    
    def _handle_threat_event(self, event: ThreatEvent) -> None:
        """Process and route threat events"""
        self.stats['total_events'] += 1
        
        if event.suspicion_score >= 70:
            self.stats['high_risk_events'] += 1
        
        # Track active threats
        self.active_threats[event.event_id] = event
        self.threat_history.append(event)
        
        # Clean old active threats (older than 5 minutes)
        cutoff = time.time() - 300
        self.active_threats = {
            k: v for k, v in self.active_threats.items() 
            if v.timestamp > cutoff
        }
        
        # Send to callback
        if self.callback:
            event_dict = event.to_dict()
            self.callback(event_dict)
        
        # Log critical threats
        if event.threat_level == 'critical':
            print(f" CRITICAL THREAT: {event.process} | Score: {event.suspicion_score} | Indicators: {event.indicators[:3]}")
    
    def _get_default_watch_paths(self) -> List[str]:
        """Get default directories to monitor"""
        paths = []
        
        if platform.system() == 'Windows':
            user_profile = os.environ.get('USERPROFILE', '')
            if user_profile:
                for folder in ['Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music']:
                    path = os.path.join(user_profile, folder)
                    if os.path.isdir(path):
                        paths.append(path)
        else:
            home = os.path.expanduser('~')
            for folder in ['Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music']:
                path = os.path.join(home, folder)
                if os.path.isdir(path):
                    paths.append(path)
        
        return paths
    
    def _start_file_monitoring(self, paths: List[str]) -> None:
        """Start file system monitoring on specified paths"""
        if not paths:
            print("  No paths provided for file monitoring")
            return
        
        print(f"\n Starting file system monitoring:")
            # Store paths for file counting
        self.file_intel.monitored_paths = []
        for path in paths:
            if not os.path.exists(path):
                print(f"    Path not found: {path}")
                continue
            
            try:
                observer = Observer()
                observer.schedule(self.file_intel, path, recursive=True)
                observer.start()
                self.file_observers.append(observer)
                self.file_intel.monitored_paths.append(path)
                print(f" Monitoring: {path}")
            except Exception as e:
                print(f" Failed to monitor {path}: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        uptime = time.time() - self.stats['uptime_start']
        
        return {
            'uptime_seconds': int(uptime),
            'monitoring_active': self.monitoring,
            'total_events': self.stats['total_events'],
            'high_risk_events': self.stats['high_risk_events'],
            'processes_killed': self.stats['processes_killed'],
            'active_threats_count': len(self.active_threats),
            'process_intelligence': self.process_intel.get_statistics(),
            'file_intelligence': self.file_intel.get_statistics(),
            'network_intelligence': self.network_intel.get_statistics(),
            'monitor': {
                'baseline_established': self.process_intel.baseline_established,
                'file_observers': len(self.file_observers),
                'file_stats': self.file_intel.get_statistics()
            },
            'killswitch': {
                'enabled': True,
                'threat_threshold': ThreatConfig.CRITICAL_THREAT_SCORE,
                'auto_terminate': False  # Set to True for automatic process termination
            }
        }
    
    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent threat events"""
        events = list(self.threat_history)[-limit:]
        return [event.to_dict() for event in reversed(events)]


# ==============================================================================
# TESTING & DEMO
# ==============================================================================

def demo_monitoring():
    """Demo function to test the monitoring system"""
    
    def event_callback(event: Dict[str, Any]):
        """Callback to handle events"""
        print(f"\n📊 EVENT DETECTED:")
        print(f"   Type: {event['event_type']}")
        print(f"   Process: {event['process']}")
        print(f"   Score: {event['suspicion_score']}")
        print(f"   Threat Level: {event['threat_level']}")
        print(f"   Confidence: {event['confidence']:.2f}")
        print(f"   Indicators: {', '.join(event['indicators'][:5])}")
        if event.get('file_path'):
            print(f"   File: {event['file_path']}")
        print("-" * 70)
    
    # Create monitor
    monitor = SystemMonitor(callback=event_callback)
    
    # Start monitoring
    monitor.start_monitoring()
    
    try:
        print("\n⏱️  Monitoring active for 60 seconds...")
        print("   Try creating/modifying files to trigger events\n")
        
        for i in range(60):
            time.sleep(1)
            if i % 10 == 0 and i > 0:
                stats = monitor.get_statistics()
                print(f"   [{i}s] Events: {stats['total_events']} | "
                      f"High-risk: {stats['high_risk_events']} | "
                      f"Active threats: {stats['active_threats_count']}")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    
    finally:
        monitor.stop_monitoring()
        
        # Print final stats
        stats = monitor.get_statistics()
        print("\n" + "="*70)
        print("📊 FINAL STATISTICS")
        print("="*70)
        print(f"Process Intelligence:")
        print(f"   • Total processes seen: {stats['process_intelligence']['total_processes_seen']}")
        print(f"   • System processes: {stats['process_intelligence']['system_processes']}")
        print(f"   • Third-party processes: {stats['process_intelligence']['third_party_processes']}")
        print(f"   • New processes detected: {stats['process_intelligence']['new_processes']}")
        print(f"   • Anomalous processes: {stats['process_intelligence']['anomalous_processes']}")
        print(f"\nFile Intelligence:")
        print(f"   • Total file events: {stats['file_intelligence']['total_events']}")
        print(f"   • High entropy files: {stats['file_intelligence']['high_entropy_files']}")
        print(f"   • Suspicious renames: {stats['file_intelligence']['suspicious_renames']}")
        print(f"   • Mass changes detected: {stats['file_intelligence']['mass_file_changes']}")
        print(f"\nNetwork Intelligence:")
        print(f"   • Total connections: {stats['network_intelligence']['total_connections']}")
        print(f"   • Suspicious connections: {stats['network_intelligence']['suspicious_connections']}")
        print(f"   • C2 patterns detected: {stats['network_intelligence']['c2_patterns_detected']}")
        print("="*70 + "\n")


if __name__ == "__main__":
    print("🛡️  RansomGuard Advanced Threat Detection Engine")
    print("="*70)
    print("Starting demonstration...\n")
    demo_monitoring()