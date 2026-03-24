"""
engine.py — Optimized SysGuard Monitor (Cross-Platform)
- Non-blocking background monitor
- Silent logging to SQLite only (no alerts/notifications)
- Crash handling with graceful degradation
- Memory optimized with bounded caches and periodic cleanup
- Supports: Windows, macOS, Linux
"""
import threading
import time
import os
import platform
import hashlib
import subprocess
import logging
import sys
from collections import OrderedDict
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

# Platform detection
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_MACOS = SYSTEM == "Darwin"
IS_LINUX = SYSTEM == "Linux"

# Cross-platform paths
def get_temp_dirs():
    """Get platform-appropriate temp directories."""
    dirs = []
    if IS_WINDOWS:
        for var in ["TEMP", "TMP", "LOCALAPPDATA"]:
            val = os.environ.get(var)
            if val:
                dirs.append(val)
    else:
        dirs.extend(["/tmp", "/var/tmp", "/var/folders"])
    # Add user home temp
    dirs.append(os.path.expanduser("~/tmp"))
    return [d for d in dirs if os.path.isdir(d)] or ["/tmp"]

TEMP_DIRS = get_temp_dirs()

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# Setup logging
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sysguard.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Cross-platform safe processes (system processes to skip)
SAFE_PROCESSES_WINDOWS = {
    "system", "idle", "dwm.exe", "csrss.exe", "smss.exe", 
    "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe",
    "explorer.exe", "taskhostw.exe", "runtimebroker.exe",
    "searchui.exe", "searchindexer.exe", "sihost.exe",
}
SAFE_PROCESSES_MACOS = {
    "kernel_task", "launchd", "windowserver", "loginwindow",
    "coreaudiod", "coreservicesd", "configd", "airportd",
}
SAFE_PROCESSES_LINUX = {
    "systemd", "init", "kthreadd", "ksoftirqd", "kworker",
    "Xorg", "gnome-shell", "gdm", "dbus-daemon",
}

def get_safe_processes():
    if IS_WINDOWS:
        return SAFE_PROCESSES_WINDOWS
    elif IS_MACOS:
        return SAFE_PROCESSES_MACOS
    else:
        return SAFE_PROCESSES_LINUX

SAFE_PROCESSES = get_safe_processes()

# Cross-platform suspicious ports
SUSPICIOUS_PORTS = frozenset({4444, 5555, 6666, 1337, 9999, 31337, 5900, 5800})

# Platform-specific screen DLLs
SCREEN_DLLS = frozenset([
    "dxgi.dll", "d3d11.dll", "gdi32.dll", "opengl32.dll",
    "nvfbc.dll", "d3d9.dll", "d3d12.dll",
]) if IS_WINDOWS else frozenset([
    # macOS frameworks
    "CoreGraphics.framework", "Quartz.framework", "AppKit.framework",
    # Linux libs
    "libX11.so", "libXext.so", "libxrender.so", "libgl.so",
])

# Cross-platform suspicious paths
SUSPICIOUS_PATHS = frozenset([
    "appdata\\local\\temp", "appdata\\roaming\\temp",
    "\\temp\\", "\\tmp\\", "/tmp/", "/var/tmp/",
    "/private/tmp/", "~/tmp/", "~\\AppData\\Local\\Temp",
])

# ── Screen-capture fingerprints ───────────────────────────────────────────────
SCREEN_PROC_KEYWORDS = frozenset([
    "obs", "fraps", "bandicam", "xsplit", "camtasia", "snagit",
    "screencap", "screenshot", "recordit", "gyroflow", "nvidia share",
    "shadowplay", "geforce", "amdrsserv", "dxtory", "action!",
    "lightshot", "greenshot", "sharex", "flameshot", "scrot",
    "kazam", "simplescreenrecorder", "peek", "vokoscreen",
])
SCREEN_DLLS = frozenset([
    "dxgi.dll", "d3d11.dll", "gdi32.dll", "opengl32.dll",
    "nvfbc.dll", "d3d9.dll", "d3d12.dll",
])
SCREEN_FILE_EXTS = frozenset({".mp4", ".avi", ".mkv", ".wmv", ".flv", ".mov", ".gif"})
SCREEN_FILE_KEYWORDS = frozenset(["screen", "capture", "record", "screenshot", "clip"])

# ── Mouse / remote fingerprints ─────────────────────────────────────────────
MOUSE_PROC_KEYWORDS = frozenset([
    "mousehook", "keylogger", "hook", "spy", "monitor", "logger",
    "inputcap", "remotepc", "teamviewer", "anydesk", "vnc",
    "rustdesk", "ultraviewer", "dameware", "logmein", "splashtop",
])

# ── General ───────────────────────────────────────────────────────────────────
SUSPICIOUS_PATHS = frozenset([
    "appdata\\local\\temp", "\\temp\\", "\\tmp\\",
    "roaming", "/tmp/", "/var/tmp/",
])
SUSPICIOUS_PORTS = frozenset({4444, 5555, 6666, 1337, 9999, 31337, 5900, 5800})

# ── Parent chain: apps that should NOT be spawning random child EXEs ──────────
# Windows
SUSPICIOUS_PARENTS_WINDOWS = frozenset({
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "iexplore.exe", "safari.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "acrord32.exe",
    "slack.exe", "teams.exe", "zoom.exe", "discord.exe", "telegram.exe",
    "whatsapp.exe", "skype.exe",
    "vlc.exe", "wmplayer.exe", "spotify.exe",
})
# macOS
SUSPICIOUS_PARENTS_MACOS = frozenset({
    "Safari", "Google Chrome", "Firefox", "Microsoft Edge", "Opera",
    "Notes", "Mail", "Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint",
    "Slack", "Teams", "Zoom", "Discord", "Telegram",
    "VLC", "Spotify",
})
# Linux
SUSPICIOUS_PARENTS_LINUX = frozenset({
    "firefox", "chrome", "chromium", "brave", "opera",
    "libreoffice", "evolution", "thunderbird",
    "slack", "teams", "zoom", "discord", "telegram",
    "vlc", "rhythmbox", "spotify",
})

def get_suspicious_parents():
    if IS_WINDOWS:
        return SUSPICIOUS_PARENTS_WINDOWS
    elif IS_MACOS:
        return SUSPICIOUS_PARENTS_MACOS
    else:
        return SUSPICIOUS_PARENTS_LINUX

SUSPICIOUS_PARENTS = get_suspicious_parents()

# Platform-safe children
SAFE_CHILDREN = frozenset({
    "conhost.exe", "werfault.exe", "dwm.exe",  # Windows
    "CoreFoundation", "launchd", "cfprefsd",   # macOS
    "systemd", "dbus-daemon", "gmain",         # Linux
})

# ── Thresholds ────────────────────────────────────────────────────────────────
NET_SPIKE_MB = 5
GDI_HANDLE_THRESHOLD = 150
ETW_EVENT_THRESHOLD = 10
MAX_CACHE_SIZE = 500  # Bounded cache for memory optimization
CLEANUP_INTERVAL = 60  # seconds between cache cleanups


class LRUCache:
    """Simple LRU cache with bounded size for memory optimization."""
    def __init__(self, maxsize=500):
        self.cache = OrderedDict()
        self.maxsize = maxsize
    
    def get(self, key):
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        return None
    
    def set(self, key, value):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.maxsize:
            # Remove oldest items (first 10%)
            for _ in range(self.maxsize // 10):
                self.cache.popitem(last=False)
    
    def clear(self):
        self.cache.clear()
    
    def __contains__(self, key):
        return key in self.cache
    
    def __len__(self):
        return len(self.cache)


class MonitorEngine:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._stop = threading.Event()
        self._thread = None
        self._cleanup_thread = None
        
        # Bounded caches for memory optimization
        self._seen_pids = LRUCache(MAX_CACHE_SIZE)
        self._dll_seen = LRUCache(MAX_CACHE_SIZE)
        self._net_seen = LRUCache(MAX_CACHE_SIZE)
        self._net_baseline = LRUCache(MAX_CACHE_SIZE)
        self._file_seen = LRUCache(MAX_CACHE_SIZE)
        self._proc_hashes = LRUCache(MAX_CACHE_SIZE)
        
        # Process name lookups - avoid repeated psutil calls
        self._proc_name_cache = LRUCache(MAX_CACHE_SIZE)
        
        # Alert tracking (deduplication)
        self._screen_pids = LRUCache(MAX_CACHE_SIZE)
        self._mouse_pids = LRUCache(MAX_CACHE_SIZE)
        
        # Behavior tracking
        self._net_io_last = {}
        self._net_spike_alerted = LRUCache(MAX_CACHE_SIZE)
        self._parent_alerted = LRUCache(MAX_CACHE_SIZE)
        self._gdi_alerted = LRUCache(MAX_CACHE_SIZE)
        
        self._baseline_done = False
        self._last_cleanup = time.time()

    # ── Public ────────────────────────────────────────────────────────────────
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="SysGuard-Engine")
        self._thread.start()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="SysGuard-Cleanup")
        self._cleanup_thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def update_config(self, cfg):
        self.cfg = cfg

    # ── Cleanup loop for memory management ─────────────────────────────────────
    def _cleanup_loop(self):
        while not self._stop.is_set():
            self._stop.wait(CLEANUP_INTERVAL)
            if self._stop.is_set():
                break
            try:
                self._perform_cleanup()
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")

    def _perform_cleanup(self):
        """Periodic cleanup to prevent memory leaks."""
        # Clean up stale network I/O entries
        current_time = time.time()
        stale_keys = [
            k for k, v in self._net_io_last.items()
            if current_time - v[1] > 300  # 5 min stale
        ]
        for k in stale_keys:
            self._net_io_last.pop(k, None)
        
        # Force cache cleanup if too large
        if len(self._seen_pids) > MAX_CACHE_SIZE * 1.5:
            self._seen_pids.clear()
        if len(self._net_seen) > MAX_CACHE_SIZE * 1.5:
            self._net_seen.clear()
            
        logger.debug(f"Cleanup complete. Cache sizes: pids={len(self._seen_pids)}, net={len(self._net_seen)}")

    # ── Main loop ─────────────────────────────────────────────────────────────
    def _run(self):
        try:
            if not PSUTIL_OK:
                self._log("SYSTEM", "WARN", "psutil not installed — monitoring disabled.")
                return

            self._log("SYSTEM", "INFO", "SysGuard v3 started — optimized silent monitoring")
            self._baseline_network()
            self._baseline_done = True
            self._prime_cpu()
            self._prime_net_io()

            # ETW listener — Windows only
            if platform.system() == "Windows":
                threading.Thread(
                    target=self._etw_listener, daemon=True, name="SysGuard-ETW",
                    args=(lambda: self._stop.is_set(),)
                ).start()

            while not self._stop.is_set():
                interval = self.cfg.get("scan_interval", 8)
                try:
                    self._check_screen_capture()
                    self._check_mouse_hooks()
                    self._check_processes()
                    self._check_dlls()
                    self._check_network()
                    self._check_disk()
                    self._check_temp_files()
                    # Behavior checks
                    self._check_net_volume_anomaly()
                    self._check_parent_chain()
                    self._check_gdi_handles()
                except Exception as e:
                    logger.error(f"Engine cycle error: {e}")
                self._stop.wait(interval)

            self._log("SYSTEM", "INFO", "SysGuard engine stopped.")
        except Exception as e:
            logger.critical(f"Fatal engine error: {e}")
            self._log("SYSTEM", "CRITICAL", f"Fatal error: {e}")

    def _log(self, category, severity, message, **kwargs):
        """Silent logging to database only - no stdout, no alerts."""
        try:
            from db import insert_alert
            insert_alert(category, severity, message, **kwargs)
        except Exception:
            pass  # Never crash on logging failure

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _get_proc_name(self, pid):
        """Cached process name lookup."""
        if pid in self._proc_name_cache:
            return self._proc_name_cache.get(pid)
        try:
            name = psutil.Process(pid).name()
            self._proc_name_cache.set(pid, name)
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _prime_cpu(self):
        try:
            for p in psutil.process_iter():
                try:
                    p.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    def _prime_net_io(self):
        now = time.time()
        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    io = proc.io_counters()
                    self._net_io_last[proc.pid] = (io.write_bytes, now)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    def _md5(self, path):
        try:
            h = hashlib.md5()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    # ══════════════════════════════════════════════════════════════════════════
    # DETECTOR 1 — Outbound data volume anomaly
    # ══════════════════════════════════════════════════════════════════════════
    def _check_net_volume_anomaly(self):
        threshold = NET_SPIKE_MB * 1024 * 1024
        cooldown = 60
        now = time.time()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.pid
                name = proc.info["name"] or "?"

                try:
                    io = proc.io_counters()
                    sent = io.write_bytes
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    continue

                prev_sent, _ = self._net_io_last.get(pid, (sent, now))
                self._net_io_last[pid] = (sent, now)
                delta = sent - prev_sent

                if delta < threshold:
                    continue

                last_alerted = self._net_spike_alerted.get(pid, 0)
                if (now - last_alerted) < cooldown:
                    continue

                self._net_spike_alerted.set(pid, now)
                delta_mb = delta / (1024 * 1024)

                known_safe = any(k in name.lower() for k in [
                    "chrome", "firefox", "edge", "onedrive", "dropbox",
                    "backup", "update", "steam", "google", "mega",
                ])
                severity = "WARN" if known_safe else "ALERT"

                self._log(
                    "NETWORK", severity,
                    f"Large data spike: {name} sent {delta_mb:.1f} MB in one scan interval",
                    pid=pid, proc_name=name,
                    detail=(
                        f"EXE: {proc.info['exe']} | Delta: {delta_mb:.2f} MB | "
                        f"Threshold: {NET_SPIKE_MB} MB"
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ══════════════════════════════════════════════════════════════════════════
    # DETECTOR 2 — Parent process chain suspicion
    # ══════════════════════════════════════════════════════════════════════════
    def _check_parent_chain(self):
        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "create_time"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                exe = proc.info["exe"] or ""

                if pid in self._parent_alerted:
                    continue

                age = time.time() - (proc.info.get("create_time") or time.time())
                if age > 300:
                    continue

                if name in SAFE_CHILDREN:
                    continue

                ppid = proc.info.get("ppid")
                if not ppid:
                    continue

                try:
                    parent = psutil.Process(ppid)
                    parent_name = (parent.name() or "").lower()
                    parent_exe = (parent.exe() or "").lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                if parent_name in SUSPICIOUS_PARENTS and exe:
                    self._parent_alerted.set(pid, True)
                    self._log(
                        "PROCESS", "ALERT",
                        f"Suspicious spawn: {parent_name} launched {proc.info['name']}",
                        pid=pid, proc_name=proc.info["name"],
                        detail=f"Parent: {parent_name} (PID {ppid}) | Age: {age:.0f}s"
                    )

                interpreters = ["python", "node", "ruby", "perl",
                               "powershell", "wscript", "cscript", "bash", "sh", "cmd"]
                if any(i in parent_name for i in interpreters) and pid not in self._parent_alerted:
                    self._parent_alerted.set(pid, True)
                    self._log(
                        "PROCESS", "WARN",
                        f"EXE spawned by script interpreter: {parent_name} → {proc.info['name']}",
                        pid=pid, proc_name=proc.info["name"],
                        detail=f"Interpreter: {parent_name} (PID {ppid})"
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ══════════════════════════════════════════════════════════════════════════
    # DETECTOR 3a — GDI handle count anomaly (Windows only)
    # ══════════════════════════════════════════════════════════════════════════
    def _check_gdi_handles(self):
        if platform.system() != "Windows":
            return
        try:
            import ctypes
            _user32 = ctypes.windll.user32
            _kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_INFORMATION = 0x0400
        except Exception:
            return

        SYSTEM_NAMES = {"system", "idle", "dwm.exe", "csrss.exe", "smss.exe", "lsass.exe", "services.exe"}

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.pid
                name = (proc.info["name"] or "?").lower()

                if pid in self._gdi_alerted or pid <= 4:
                    continue
                if name in SYSTEM_NAMES:
                    continue

                handle = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
                if not handle:
                    continue
                gdi_count = _user32.GetGuiResources(handle, 0)
                usr_count = _user32.GetGuiResources(handle, 1)
                _kernel32.CloseHandle(handle)

                if gdi_count > GDI_HANDLE_THRESHOLD:
                    self._gdi_alerted.set(pid, True)
                    self._log(
                        "SCREEN", "ALERT",
                        f"GDI handle overload — active screen capture: {proc.info['name']}",
                        pid=pid, proc_name=proc.info["name"],
                        detail=f"GDI: {gdi_count} | Threshold: {GDI_HANDLE_THRESHOLD}"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue

    # ══════════════════════════════════════════════════════════════════════════
    # DETECTOR 3b — ETW (Event Tracing for Windows) screen API rate
    # ══════════════════════════════════════════════════════════════════════════
    def _etw_listener(self, stop_check):
        if platform.system() != "Windows":
            return

        ps_script = r"""
try {
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        'Microsoft-Windows-Win32k/Operational',
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        '*[System[(EventID=1 or EventID=10 or EventID=100 or EventID=200)]]'
    )
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    $pids = @{}
    $count = 0
    while ($count -lt 200) {
        $evt = $reader.ReadEvent()
        if ($evt -eq $null) { break }
        $p = $evt.ProcessId
        if ($pids.ContainsKey($p)) { $pids[$p]++ } else { $pids[$p] = 1 }
        $count++
    }
    foreach ($k in $pids.Keys) { Write-Output "ETW|$k|$($pids[$k])" }
} catch { Write-Output "ETW_UNAVAILABLE" }
"""
        try:
            result = subprocess.run(
                ["powershell", "-WindowStyle", "Hidden",
                 "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=20
            )
            if not result.stdout or "ETW_UNAVAILABLE" in result.stdout:
                return

            for line in result.stdout.splitlines():
                if not line.startswith("ETW|"):
                    continue
                parts = line.split("|")
                if len(parts) < 3:
                    continue
                try:
                    epid = int(parts[1])
                    count = int(parts[2])
                except ValueError:
                    continue

                if count < ETW_EVENT_THRESHOLD:
                    continue
                try:
                    pname = psutil.Process(epid).name()
                    pexe = psutil.Process(epid).exe()
                except Exception:
                    pname = f"PID {epid}"
                    pexe = "?"

                self._log(
                    "SCREEN", "CRITICAL",
                    f"ETW: Repeated screen API calls — {pname} ({count} events)",
                    pid=epid, proc_name=pname,
                    detail=f"Win32k ETW events: {count} | EXE: {pexe}"
                )
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

    # ── Original checks ───────────────────────────────────────────────────────
    def _check_screen_capture(self):
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                exe = (proc.info["exe"] or "").lower()
                
                kw = next((k for k in SCREEN_PROC_KEYWORDS if k in name or k in exe), None)
                if kw and pid not in self._screen_pids:
                    self._screen_pids.set(pid, True)
                    self._log(
                        "SCREEN", "ALERT",
                        f"Screen capture tool: {proc.info['name']}",
                        pid=pid, proc_name=proc.info["name"],
                        detail=f"Keyword: '{kw}' | EXE: {proc.info['exe']}"
                    )
                
                # Limit memory maps iteration
                try:
                    for m in proc.memory_maps()[:20]:  # Limit to first 20 maps
                        ml = m.path.lower()
                        for dll in SCREEN_DLLS:
                            if dll in ml:
                                dll_key = f"{pid}:{dll}"
                                if dll_key not in self._dll_seen:
                                    self._dll_seen.set(dll_key, True)
                                    self._log(
                                        "SCREEN", "WARN",
                                        f"Screen DLL loaded: {dll} by {proc.info['name']}",
                                        pid=pid, proc_name=proc.info["name"],
                                        detail=f"DLL: {m.path}"
                                    )
                except (psutil.AccessDenied, AttributeError):
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Check open files (limit iterations)
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                for f in proc.open_files()[:10]:  # Limit files checked
                    fl = f.path.lower()
                    ext = os.path.splitext(fl)[1]
                    if (any(k in fl for k in SCREEN_FILE_KEYWORDS) or ext in SCREEN_FILE_EXTS):
                        file_key = f"{pid}:{f.path}"
                        if file_key not in self._file_seen:
                            self._file_seen.set(file_key, True)
                            self._log(
                                "SCREEN", "ALERT",
                                f"Recording file open: {os.path.basename(f.path)}",
                                pid=pid, proc_name=proc.info["name"],
                                detail=f"Path: {f.path}"
                            )
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue

    def _check_mouse_hooks(self):
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                exe = (proc.info["exe"] or "").lower()
                
                kw = next((k for k in MOUSE_PROC_KEYWORDS if k in name or k in exe), None)
                if kw and pid not in self._mouse_pids:
                    self._mouse_pids.set(pid, True)
                    self._log(
                        "MOUSE", "ALERT",
                        f"Remote/hook tool: {proc.info['name']}",
                        pid=pid, proc_name=proc.info["name"],
                        detail=f"Keyword: '{kw}' | EXE: {proc.info['exe']}"
                    )
                
                try:
                    for c in proc.connections(kind="inet")[:10]:  # Limit connections
                        if c.raddr and c.raddr.port in (5900, 5800, 5901):
                            key = f"{pid}:{c.raddr.ip}:{c.raddr.port}"
                            if key not in self._net_seen:
                                self._net_seen.set(key, True)
                                self._log(
                                    "MOUSE", "CRITICAL",
                                    f"VNC/remote connection: {proc.info['name']} → {c.raddr.ip}:{c.raddr.port}",
                                    pid=pid, proc_name=proc.info["name"],
                                    detail=f"Remote: {c.raddr.ip}:{c.raddr.port}"
                                )
                except (psutil.AccessDenied, AttributeError):
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _check_processes(self):
        susp_paths = self.cfg.get("suspicious_paths", list(SUSPICIOUS_PATHS))
        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                pid = proc.info["pid"]
                exe = (proc.info["exe"] or "").lower()
                name = proc.info["name"] or ""
                
                if pid not in self._seen_pids:
                    self._seen_pids.set(pid, True)
                    if exe and any(p in exe for p in susp_paths):
                        self._log(
                            "PROCESS", "ALERT",
                            f"Process in suspicious path: {name}",
                            pid=pid, proc_name=name,
                            detail=f"EXE: {proc.info['exe']}"
                        )
                    real = proc.info["exe"]
                    if real and os.path.exists(real):
                        h = self._md5(real)
                        if h:
                            self._proc_hashes.set(pid, (real, h))
                else:
                    cached = self._proc_hashes.get(pid)
                    if cached:
                        stored_exe, stored_hash = cached
                        if os.path.exists(stored_exe):
                            cur = self._md5(stored_exe)
                            if cur and cur != stored_hash:
                                self._proc_hashes.set(pid, (stored_exe, cur))
                                self._log(
                                    "INTEGRITY", "CRITICAL",
                                    f"Binary tampered while running: {name}",
                                    pid=pid, proc_name=name,
                                    detail=f"EXE: {stored_exe}"
                                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _check_dlls(self):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or ""
                for m in proc.memory_maps()[:20]:  # Limit iteration
                    ml = m.path.lower()
                    for dll in SCREEN_DLLS:
                        dll_key = f"{pid}:{dll}"
                        if dll in ml and dll_key not in self._dll_seen:
                            self._dll_seen.set(dll_key, True)
                            if pid not in self._screen_pids:
                                self._log(
                                    "DLL", "WARN",
                                    f"Screen DLL: {dll} by {name}",
                                    pid=pid, proc_name=name,
                                    detail=f"Path: {m.path}"
                                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue

    def _baseline_network(self):
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.raddr:
                    key = f"{c.pid}:{c.raddr.ip}:{c.raddr.port}"
                    self._net_baseline.set(key, True)
        except Exception:
            pass

    def _check_network(self):
        if not self.cfg.get("alert_on_suspicious_net", True):
            return
        susp_ports = SUSPICIOUS_PORTS | set(self.cfg.get("suspicious_ports", []))
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        for c in conns:
            if not c.raddr:
                continue
            key = f"{c.pid}:{c.raddr.ip}:{c.raddr.port}"
            if key in self._net_seen or key in self._net_baseline:
                continue
            self._net_seen.set(key, True)
            port = c.raddr.port
            ip = c.raddr.ip
            try:
                pname = psutil.Process(c.pid).name() if c.pid else "?"
            except Exception:
                pname = "?"
            if port in susp_ports:
                self._log("NETWORK", "CRITICAL",
                    f"Connection to malicious port {port}: {pname}",
                    pid=c.pid, proc_name=pname, detail=f"Remote: {ip}:{port}")
            elif port not in (80, 443, 53) or self.cfg.get("net_log_all"):
                self._log("NETWORK", "WARN",
                    f"New outbound: {pname} → {ip}:{port}",
                    pid=c.pid, proc_name=pname, detail=f"Remote: {ip}:{port}")

    def _check_disk(self):
        threshold = self.cfg.get("disk_write_threshold_mb", 50) * 1024 * 1024
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                io = proc.io_counters()
                if io.write_bytes > threshold:
                    self._log("DISK", "WARN",
                        f"High disk write: {proc.info['name']} — {io.write_bytes//(1024*1024)} MB",
                        pid=proc.info["pid"], proc_name=proc.info["name"],
                        detail=f"write_bytes={io.write_bytes}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue

    def _check_temp_files(self):
        dirs_to_check = []
        if platform.system() == "Windows":
            t = os.environ.get("TEMP") or os.environ.get("TMP")
            if t:
                dirs_to_check.append(t)
        else:
            dirs_to_check.extend(["/tmp", "/var/tmp"])
        
        for d in dirs_to_check:
            try:
                # Limit directory listing
                entries = os.listdir(d)[:100]  # Limit entries checked
                for fname in entries:
                    ext = os.path.splitext(fname)[1].lower()
                    key = os.path.join(d, fname)
                    if key in self._file_seen:
                        continue
                    if ext in SCREEN_FILE_EXTS or any(k in fname.lower() for k in SCREEN_FILE_KEYWORDS):
                        self._file_seen.set(key, True)
                        try:
                            size_mb = os.path.getsize(key) / (1024 * 1024)
                        except:
                            size_mb = 0
                        self._log("FILE", "ALERT",
                            f"Recording file in temp: {fname} ({size_mb:.1f} MB)",
                            detail=f"Path: {key}")
            except Exception:
                pass
