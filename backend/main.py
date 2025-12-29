"""
==============================================================================
RansomGuard - Main Backend Server (Production Rewrite)

Usage:  uvicorn main:app --host 127.0.0.1 --port 8000 --reload

==============================================================================
"""

import asyncio
import logging
import os
import sys
import time
from typing import Dict, List, Optional
from backend.detector import ThreatDetector


from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel
from collections import deque
from backend.response import AutomatedResponse
from backend.chat_assistant import RansomGuardChatbot



import sys
import io

# Force UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


# --------------------- Path setup (optional) ---------------------------------
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, BACKEND_DIR)
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

# --------------------- Logging ------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ransomguard")

# --------------------- Import project modules (with safe stubs) ---------------
try:
    from utils.database import Database
    logger.info(" Database imported")
except Exception as e:
    logger.warning(f"Database import failed: {e} — using stub")

    class Database:
        async def init_db(self):
            logger.info("[DB stub] init_db")

        async def close(self):
            logger.info("[DB stub] close")

        async def log_event(self, event: dict):
            logger.debug("[DB stub] log_event: %s", event)

        async def get_recent_logs(self, limit: int = 50):
            return []

try:
    from ml_model.train_model import RansomwareMLModel 
    logger.info(" ML model imported")
except Exception as e:
    logger.warning(f"ML model import failed: {e} — using stub")

    class RansomwareMLModel:
        def __init__(self):
            self.loaded = False

        def load_model(self) -> bool:
            logger.info("[ML stub] load_model")
            self.loaded = False
            return False

        def predict(self, features: dict) -> dict:
            # Predict structure: {'is_ransomware': False, 'confidence': 0}
            return {"is_ransomware": False, "confidence": 0}

try:
    from ml_model.feature_extractor import FeatureExtractor
    logger.info(" FeatureExtractor imported")
except Exception as e:
    logger.warning(f"FeatureExtractor import failed: {e} — using stub")

    class FeatureExtractor:
        def __init__(self):
            pass

        def update_process_metrics(self, pid: int, **metrics):
            logger.debug("[FE stub] update_process_metrics pid=%s metrics=%s", pid, metrics)

        def update_process_activity(self, pid: int, event_type: str, event_data: dict):
            logger.debug("[FE stub] update_process_activity pid=%s type=%s", pid, event_type)

        def extract_features(self, pid: int) -> dict:
            return {}

# ========================================================================
# CRITICAL: Import Real SystemMonitor (NO STUB FALLBACK)
# ========================================================================
try:
    from monitor import SystemMonitor
    logger.info("Real SystemMonitor imported from monitor.py")
    USING_REAL_MONITOR = True
    
    # Verify it's the real one
    if hasattr(SystemMonitor, '_loop'):
        logger.error("CRITICAL: Imported STUB monitor instead of real one!")
        raise ImportError("Wrong monitor imported - stub instead of real")
    
except Exception as e:
    logger.error("="*70)
    logger.error(" CRITICAL FAILURE: Cannot import real SystemMonitor!")
    logger.error(f"   Error: {e}")
    logger.error("   System will NOT detect any threats!")
    logger.error("="*70)
    
    # Print full traceback for debugging
    import traceback
    traceback.print_exc()
    
    # REFUSE to start without real monitor
    raise ImportError(f"Cannot start RansomGuard without real monitor: {e}")


try:
    from killswitch import KillSwitch
    logger.info(" KillSwitch imported")
except Exception as e:
    logger.warning(f"KillSwitch import failed: {e} — using stub")

    class KillSwitch:
        def __init__(self, enable_auto_kill=True, threat_threshold=75):
            self.enabled = enable_auto_kill
            self.threat_threshold = threat_threshold

        def evaluate_threat(self, event: dict) -> dict:
            # Return a dict containing 'action_taken' (none/terminated) and metadata
            return {
                "action_taken": "none",
                "process": event.get("process", "unknown"),
                "score": event.get("suspicion_score", 0),
                "timestamp": time.time(),
                "success": False,
                "message": "kill-switch stub"
            }

        def get_statistics(self) -> dict:
            return {"enabled": self.enabled, "total_killed": 0, "currently_blocked": 0}

        def get_kill_history(self, limit=50):
            return []

        def get_blocked_processes(self):
            return []

try:
    from behavioral_analyzer import BehavioralAnalyzer
    logger.info("BehavioralAnalyzer imported")
except Exception as e:
    logger.warning(f"BehavioralAnalyzer import failed: {e} — using stub")

    class BehavioralAnalyzer:
        def get_statistics(self):
            return {"tracked_processes": 0}

# --------------------- Configuration -----------------------------------------
class Configuration:
    def __init__(self):
        self.settings = {
            'system.name': 'RansomGuard Detection System',
            'system.version': '2.0.0',
            'server.host': '127.0.0.1',
            'server.port': 8000,
            'killswitch.enabled': True,
            'killswitch.threat_threshold': 75,
            'monitoring.process_interval': 1,
            'monitoring.min_score': 0,
            'alerts.enabled': True,
            'alerts.threshold': 70,
            'alerts.max_per_minute': 1,
            'performance.max_events': 500,
            'performance.update_interval': 0.1,
        }

    def get(self, key: str, default=None):
        return self.settings.get(key, default)

    def set(self, key: str, value):
        self.settings[key] = value

    @property
    def killswitch_enabled(self) -> bool:
        return self.settings.get('killswitch.enabled', True)

    @property
    def killswitch_threshold(self) -> int:
        return self.settings.get('killswitch.threat_threshold', 75)

config = Configuration()

# --------------------- FastAPI app -------------------------------------------
app = FastAPI(
    title=config.get('system.name'),
    version=config.get('system.version'),
    description="Advanced AI-Powered Ransomware Detection System",
    docs_url="/api/docs",
    redoc_url="/api/redoc",

)
# Initialize chatbot (add right after the app creation)
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY", "") #enter the API key inside the inverted comma 
chatbot = RansomGuardChatbot(api_key=PERPLEXITY_API_KEY)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static dashboard mounting (optional)
if os.path.isdir(DASHBOARD_DIR):
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR), name="dashboard")
    logger.info(" Dashboard mounted from: %s", DASHBOARD_DIR)
else:
    logger.info("Dashboard directory not found: %s", DASHBOARD_DIR)

# --------------------- Connection Manager -----------------------------------
class ConnectionManager:
    def __init__(self, max_connections: int = 50):
        self.active_connections: List[WebSocket] = []
        self.max_connections = max_connections
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> bool:
        async with self._lock:
            if len(self.active_connections) >= self.max_connections:
                await websocket.close(code=1008, reason="Max connections")
                return False
            self.active_connections.append(websocket)
            logger.info(" Client connected (Total: %d)", len(self.active_connections))
            return True

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
                logger.info(" Client disconnected (Total: %d)", len(self.active_connections))

    async def broadcast(self, message: dict):
        to_remove = []
        async with self._lock:
            conns = list(self.active_connections)
        for ws in conns:
            try:
                await ws.send_json(message)
            except Exception:
                to_remove.append(ws)
        for ws in to_remove:
            await self.disconnect(ws)

    async def send_to(self, websocket: WebSocket, message: dict) -> bool:
        try:
            await websocket.send_json(message)
            return True
        except Exception:
            await self.disconnect(websocket)
            return False

    def count(self) -> int:
        return len(self.active_connections)

# --------------------- Application State ------------------------------------
class ApplicationState:
    def __init__(self):
        self.manager = ConnectionManager()
        self.db = Database()
        self.ml_model = RansomwareMLModel()
        self.feature_extractor: Optional[FeatureExtractor] = None
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.kill_switch = KillSwitch(
            enable_auto_kill=config.killswitch_enabled,
            threat_threshold=config.killswitch_threshold,
        )
        self.monitor: Optional[SystemMonitor] = None

        # Async queue used by event processor
        self.event_queue: asyncio.Queue = asyncio.Queue()

        # History and stats
        self.events_history: List[dict] = []
        self.max_events = config.get('performance.max_events', 500)

        self.stats = {
            'total_events': 0,
            'high_risk_events': 0,
            'threats_blocked': 0,
            'processes_killed': 0,
            'alerts_sent': 0,
            'uptime_start': time.time(),
            'last_threat': None,
        }

        self.alert_timestamps = deque()
        self.max_alerts_per_minute = config.get('alerts.max_per_minute', 20)

    def add_event_history(self, event: dict):
        self.events_history.insert(0, event)
        if len(self.events_history) > self.max_events:
            self.events_history.pop()

        self.stats['total_events'] += 1
        score = event.get('suspicion_score', 0)
        if score >= 70:
            self.stats['high_risk_events'] += 1
            self.stats['last_threat'] = time.time()
    
    def can_send_alert(self) -> bool:
        """Check if we can send an alert based on rate limiting.
            Uses deque for O(1) operations instead of list filtering.
        """
        now = time.time()
        # Remove expired timestamps from left (older entries)
        while self.alert_timestamps and now - self.alert_timestamps[0] > 60:
            self.alert_timestamps.popleft()
        
        # Check if we've hit the limit
        if len(self.alert_timestamps) >= self.max_alerts_per_minute:
            return False
        
        # Add current timestamp
        self.alert_timestamps.append(now)
        return True

    def get_statistics(self) -> dict:
        uptime = int(time.time() - self.stats['uptime_start'])
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'events_in_memory': len(self.events_history),
            'active_connections': self.manager.count(),
            'monitoring_active': bool(self.monitor) and getattr(self.monitor, 'monitoring', False),
            'killswitch': self.kill_switch.get_statistics(),
            'behavioral': self.behavioral_analyzer.get_statistics(),
            'monitor': self.monitor.get_statistics() if self.monitor and hasattr(self.monitor, 'get_statistics') else {},
        }

app_state = ApplicationState()
app_state._main_loop = None

# --------------------- Async callback & thread-safe bridge ------------------
async def async_callback(event: dict):
    """Put event into the asyncio queue (async context)."""
    await app_state.event_queue.put(event)


def thread_safe_callback(event: dict):
    """
    Called from SystemMonitor threads; safely forwards events into
    the main asyncio loop using run_coroutine_threadsafe.
    """
    loop = app_state._main_loop
    if loop is None or not loop.is_running():
        logger.error("No running event loop bound for thread_safe_callback")
        return

    try:
        asyncio.run_coroutine_threadsafe(async_callback(event), loop)
    except Exception as e:
        logger.exception("Failed to deliver event from thread: %s", e)


# --------------------- Event Processor (async) ------------------------------

async def process_event(event: dict):
    try:
        # if app_state.detector:
        #     event = app_state.detector.analyze_event(event)
            
        score = event.get('suspicion_score', 0)
        process_name = event.get('process', 'unknown')
        event_type = event.get('type', 'unknown')

        logger.info("Processing event: %s | type=%s | score=%s", process_name, event_type, score)

        # --- Detection mode assignment (CRITICAL) ---
        if (
            event.get("rapid_file_ops", 0) > 20
            or event.get("mass_file_activity") is True
            or event.get("pre_encryption_indicator") is True
        ):
            event["detection_mode"] = "PRE_ENCRYPTION"

        elif (
            event.get("ml_prediction", {}).get("decision") in {"RANSOMWARE", "KILL"}
            and event.get("ml_prediction", {}).get("confidence", 0) >= 70
        ):
            event["detection_mode"] = "ML_CONFIRMED"

        else:
            event["detection_mode"] = "SCORE_BASED"

        # Add to history
        app_state.add_event_history(event)

        # Store to DB (fire-and-forget but awaited to handle DB errors)
        try:
            await app_state.db.log_event(event)
        except Exception:
            logger.exception("DB log_event failed")

        # Update feature extractor (non-blocking)
        pid = event.get('pid')
        if app_state.feature_extractor and pid:
            if event_type == 'process_event':
                app_state.feature_extractor.update_process_metrics(
                    pid=pid,
                    cpu=event.get('cpu_percent', 0),
                    memory=event.get('memory_percent', 0),
                    threads=event.get('threads', 0),
                )
            elif event_type == 'file_event':
                app_state.feature_extractor.update_process_activity(
                    pid=pid,
                    event_type=event.get('operation', 'unknown'),
                    event_data=event,
                )

        # Run ML model prediction
        try:
            if (
                app_state.ml_model
                and getattr(app_state.ml_model, 'loaded', True)
                and pid
                and app_state.feature_extractor
            ):
                features = app_state.feature_extractor.extract_features(pid)

                # Do not run ML if feature window is invalid
                if not features or not features.get("valid"):
                    event["ml_prediction"] = {
                        "decision": "UNAVAILABLE",
                        "confidence": None,
                        "reason": features.get("reason") if features else "no_features"
                    }
                else:
                    ml_result = app_state.ml_model.predict(features)
                    event["ml_prediction"] = ml_result

                    # 🔒 HARD GATE: only explicit ransomware decisions affect score
                    if (
                        ml_result.get("decision") in {"KILL", "RANSOMWARE"}
                        and ml_result.get("confidence") is not None
                        and ml_result.get("confidence") >= 70
                    ):
                        event["suspicion_score"] = min(
                            100, event.get("suspicion_score", 0) + 30
                        )
                        event["indicators"] = event.get("indicators", []) + [
                            "ml_ransomware_detected"
                        ]

                        logger.warning(
                            "ML confirmed ransomware | PID=%s | confidence=%s",
                            pid,
                            ml_result.get("confidence"),
                        )

        except Exception:
            logger.exception("ML prediction failed")


        # --- STEP 3: Automated response for HIGH threats ---
        if event.get("threat_level") == "HIGH":
            logger.critical(
                f"[AUTO-RESPONSE] HIGH threat | "
                f"PID={event.get('pid')} | "
                f"SCORE={event.get('suspicion_score')}"
            )
        
            logger.warning(
        f"[PIPELINE] SCORE={event.get('suspicion_score')} "
        f"LEVEL={event.get('threat_level')} "
        f"PID={event.get('pid')}"
)
            if app_state.response:
                response_result = await app_state.response.execute(event)
                event["response"] = response_result

        # Kill-switch
        try:
            if config.killswitch_enabled:
                kill_result = app_state.kill_switch.evaluate_threat(event)
                if kill_result.get('action_taken') == 'terminated':
                    app_state.stats['processes_killed'] += 1
                    app_state.stats['threats_blocked'] += 1

                # Broadcast kill result
                await app_state.manager.broadcast({
                    'type': 'killswitch',
                    'data': kill_result,
                })
                logger.info("Kill-switch evaluated for %s: %s", process_name, kill_result.get('action_taken'))
        except Exception:
            logger.exception("Kill-switch evaluation failed")

        # Broadcast activity to clients

        try:
            await app_state.manager.broadcast({
                'type': 'activity',
                'data': {
                    'process_name': process_name,
                    'process': process_name,  # Fallback for compatibility
                    'event_type': event_type,
                    'type': event_type,
                    'score': event.get('suspicion_score', 0),
                    'suspicion_score': event.get('suspicion_score', 0),
                    'pid': event.get('pid'),
                    'timestamp': event.get('timestamp', time.time()),
                    'cpu_percent': event.get('cpu_percent', 0),
                    'memory_percent': event.get('memory_percent', 0),
                    'threads': event.get('threads', 0),
                    'file_path': event.get('file_path', ''),
                    'operation': event.get('operation', ''),
                    'indicators': event.get('indicators', []),
                },
            })
        except Exception:
            logger.exception("Broadcast failed")


        # Send alert if high severity
        try:
            alert_threshold = config.get('alerts.threshold', 70)
            if config.get('alerts.enabled') and event.get('suspicion_score', 0) >= alert_threshold:
                if app_state.can_send_alert():
                    await send_alert(event)
        except Exception:
            logger.exception("Alert sending failed")

    except Exception:
        logger.exception("Unexpected error processing event")


async def event_processor():
    logger.info(" Event processor started")
    interval = config.get('performance.update_interval', 0.1)

    try:
        while True:
            try:
                event = await asyncio.wait_for(app_state.event_queue.get(), timeout=interval)
            except asyncio.TimeoutError:
                # Nothing to do, loop again
                await asyncio.sleep(0)
                continue

            # Process the event
            await process_event(event)

    except asyncio.CancelledError:
        logger.info("Event processor cancelled")
    except Exception:
        logger.exception("Event processor crashed")

async def periodic_stats_broadcaster():
    """Broadcast system stats every 5 seconds."""
    logger.info("📊 Stats broadcaster started")
    try:
        while True:
            await asyncio.sleep(5)
            
            try:
                stats = app_state.get_statistics()
                file_stats = stats.get('monitor', {}).get('file_stats', {})
                files_monitored = file_stats.get('files_monitored', 0)
                
                # STRICT CONTRACT - All fields required
                stats_data = {
                    'type': 'stats',  # ✅ Changed from 'system'
                    'data': {
                        'active_threats': stats.get('high_risk_events', 0),
                        'blocked_today': stats.get('threats_blocked', 0),
                        'files_monitored': files_monitored,
                        'protection_rate': 100,
                    }
                }
                
                # Validate required fields
                required = ['active_threats', 'blocked_today', 'files_monitored', 'protection_rate']
                for field in required:
                    if field not in stats_data['data']:
                        raise ValueError(f"Missing required field: {field}")
                
                await app_state.manager.broadcast(stats_data)
                logger.debug(f"📊 Stats: threats={stats_data['data']['active_threats']}, blocked={stats_data['data']['blocked_today']}, files={stats_data['data']['files_monitored']}")
                
            except Exception:
                logger.exception("Stats broadcast failed")
                
    except asyncio.CancelledError:
        logger.info("Stats broadcaster cancelled")


# --------------------- Alerts ------------------------------------------------
async def send_alert(event: dict):
    score = event.get('suspicion_score', 0)
    process = event.get('process', 'unknown')

    app_state.stats['alerts_sent'] += 1
    app_state.stats['threats_blocked'] += 1

    alert = {
        "type": "alert",
        "data": {
            "severity": "critical" if score >= 85 else "high",
            "process": process,
            "score": score,
            "timestamp": event.get('timestamp', time.time()),
            "indicators": event.get('indicators', []),
            "file_path": event.get('file_path', ''),
            "operation": event.get('operation', ''),
            "message": f"High-risk activity: {process}",
        },
    }

    await app_state.manager.broadcast(alert)
    logger.warning(" ALERT: %s (Score: %s)", process, score)

# --------------------- Startup / Shutdown -----------------------------------
# Keep references to background tasks so we can cancel on shutdown
_background_tasks: List[asyncio.Task] = []

@app.on_event("startup")
async def startup():
    app_state._main_loop = asyncio.get_running_loop()
    logger.info("\n Starting RansomGuard backend (production rewrite)")

    # Initialize DB
    try:
        await app_state.db.init_db()
        logger.info(" Database ready")
    except Exception:
        logger.exception("Database initialization failed")

    # Load ML model
    try:
        loaded = app_state.ml_model.load_model()
        app_state.ml_model.loaded = loaded
        if loaded:
            logger.info(" ML model loaded")
        else:
            logger.info("  ML model not loaded; continuing without ML detection")
    except Exception:
        logger.exception("ML model load failed")

    # Feature extractor
    app_state.feature_extractor = FeatureExtractor()
    logger.info(" Feature extractor initialized")

    # Initialize threat detector
    app_state.detector = ThreatDetector(config)
    logger.info(" Threat detector initialized")

    # Initialize automated response engine
    app_state.response = AutomatedResponse()
    logger.info(" Automated response engine initialized")


    # Initialize threat detector
    app_state.detector = ThreatDetector(config)
    logger.info(" Threat detector initialized")


    # Start event processor
    task = asyncio.create_task(event_processor())
    _background_tasks.append(task)
    logger.info(" Event processor running")

    # Start periodic stats broadcaster (dashboard heartbeat)
    stats_task = asyncio.create_task(periodic_stats_broadcaster())
    _background_tasks.append(stats_task)
    logger.info(" Stats broadcaster running")

    # Initialize monitor (run in separate thread if blocking)
    try:
        logger.info("[DEBUG] Creating SystemMonitor instance...")
        app_state.monitor = SystemMonitor(callback=thread_safe_callback)
        logger.info("[DEBUG] SystemMonitor instance created")
        
        logger.info("[MONITOR] Starting system monitor with default paths...")
        
        # Start monitoring - let it use default paths
        logger.info("[DEBUG] Calling start_monitoring()...")
        started = app_state.monitor.start_monitoring()  # No arguments!
        logger.info(f"[DEBUG] start_monitoring() returned: {started}")
        
        if started:
            logger.info("[OK] System monitor started successfully")
            
            # Give it a moment to initialize
            await asyncio.sleep(0.5)

            # Check status
            stats = app_state.monitor.get_statistics()
            logger.info(f"[DEBUG] File observers active: {stats.get('monitor', {}).get('file_observers', 0)}")
        else:
            logger.warning("[WARN] System monitor did not start")
            
    except Exception as e:
        logger.exception(f"[ERROR] Monitor initialization failed: {e}")

@app.on_event("shutdown")
async def shutdown():
    logger.info("\n Shutting down RansomGuard backend...")

    # Stop monitor
    try:
        if app_state.monitor:
            app_state.monitor.stop_monitoring()
            logger.info("Monitor stop requested")
    except Exception:
        logger.exception("Monitor shutdown failed")

    # Cancel background tasks
    for t in _background_tasks:
        t.cancel()

    await asyncio.sleep(0.1)

    # Close DB
    try:
        await app_state.db.close()
        logger.info("Database closed")
    except Exception:
        logger.exception("Database close failed")

    logger.info(" Shutdown complete\n")

# --------------------- API Endpoints ----------------------------------------
@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>RansomGuard</h1><p>Dashboard not installed.</p>")

@app.get("/api/status")
async def get_status():
    stats = app_state.get_statistics()
    return JSONResponse({
        "status": "online",
        "timestamp": time.time(),
        "version": config.get('system.version'),
        "statistics": stats,
        "configuration": {
            "killswitch_enabled": config.killswitch_enabled,
            "threat_threshold": config.killswitch_threshold,
            "monitoring_active": bool(app_state.monitor) and getattr(app_state.monitor, 'monitoring', False),
        },
    })

@app.get("/api/events/recent")
async def get_recent_events(limit: int = Query(50, le=100)):
    return JSONResponse(app_state.events_history[:limit])

@app.get("/api/events/count")
async def get_event_count():
    return JSONResponse({
        "total": app_state.stats['total_events'],
        "high_risk": app_state.stats['high_risk_events'],
        "in_memory": len(app_state.events_history),
    })

@app.get("/api/statistics")
async def get_statistics():
    return JSONResponse(app_state.get_statistics())

@app.get("/api/logs")
async def get_logs(limit: int = Query(50, le=100)):
    try:
        logs = await app_state.db.get_recent_logs(limit)
        return JSONResponse(logs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/killswitch/toggle")
async def toggle_killswitch(enabled: bool):
    app_state.kill_switch.enabled = enabled
    await app_state.manager.broadcast({
        "type": "system",
        "data": {
            "message": f"Kill-switch {'enabled' if enabled else 'disabled'}",
            "killswitch_enabled": enabled,
            "timestamp": time.time(),
        },
    })
    return JSONResponse({"success": True, "killswitch_enabled": enabled, "threshold": app_state.kill_switch.threat_threshold})

@app.get("/api/killswitch/history")
async def get_kill_history(limit: int = Query(50, le=100)):
    return JSONResponse(app_state.kill_switch.get_kill_history(limit))

@app.get("/api/killswitch/blocked")
async def get_blocked():
    blocked = app_state.kill_switch.get_blocked_processes()
    return JSONResponse({"blocked_processes": blocked, "count": len(blocked)})

@app.get("/health")
async def health():
    return JSONResponse({
        "ok": True,
        "timestamp": time.time(),
        "uptime": int(time.time() - app_state.stats['uptime_start']),
        "version": config.get('system.version'),
    })

# --------------------- WebSocket Endpoint ----------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    if not await app_state.manager.connect(websocket):
        return

    try:
        # Send initial bulk events ONLY
        await websocket.send_json({
            "type": "bulk",
            "data": app_state.events_history[:50],
        })
        
        # ❌ DELETED: Initial system message - not needed
        # periodic_stats_broadcaster handles all stats
        
        # Main message loop - keep alive + heartbeat ONLY
        while True:
            try:
                # Wait for client messages with 25s timeout
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=25)
                
                if msg == "ping":
                    await websocket.send_json({"type": "pong"})
                    
            except asyncio.TimeoutError:
                # Send heartbeat ping to keep connection alive
                await websocket.send_json({
                    "type": "ping",
                    "timestamp": time.time()
                })
                
            except WebSocketDisconnect:
                logger.info("WebSocket client disconnected")
                break
                
            except Exception as e:
                logger.exception(f"WebSocket error: {e}")
                break

    finally:
        await app_state.manager.disconnect(websocket)

print(">>> WebSocket /ws registered")

# ===== NEW CHAT ENDPOINTS (ADD AT BOTTOM) =====
@app.post("/api/chat")
async def chat_endpoint(request: dict):
    """Chat with RansomGuard AI Assistant"""
    user_message = request.get("message", "")
    
    if not user_message:
        return {"error": "Message is required"}
    
    result = await chatbot.chat(user_message)
    return result

@app.post("/api/chat/explain-threat")
async def explain_threat_endpoint(request: dict):
    """Get AI explanation for specific threat"""
    pid = request.get("pid")
    features = request.get("features", {})
    
    if not pid or not features:
        return {"error": "PID and features are required"}
    
    explanation = await chatbot.explain_threat(pid, features)
    return {"explanation": explanation}

@app.post("/api/chat/reset")
async def reset_chat():
    """Reset chat conversation history"""
    chatbot.reset_conversation()
    return {"success": True, "message": "Chat history cleared"}

# --------------------- Entry point for development --------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.get('server.host'), port=config.get('server.port'), log_level="info")
