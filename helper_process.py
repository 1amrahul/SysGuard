"""
helper_process.py — Optimized Headless SysGuard Background Monitor
- Silent logging to SQLite only (no alerts/notifications)
- Crash handling with graceful degradation
- Memory optimized with bounded caches
"""
import sys
import os
import time
import json
import platform
import subprocess
import threading
import logging
import signal

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import db
from engine import MonitorEngine

# Setup logging
logging.basicConfig(
    filename='sysguard.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
DEFAULT_CFG = {
    "scan_interval": 8,
    "disk_write_threshold_mb": 50,
    "net_log_all": False,
    "suspicious_paths": ["appdata\\local\\temp", "\\temp\\", "/tmp/", "roaming"],
    "suspicious_ports": [4444, 5555, 6666, 1337, 9999, 31337],
    "alert_on_suspicious_net": True,
    "alert_on_high_disk": False,
}


def load_cfg():
    if os.path.exists(CONFIG_PATH):
        try:
            c = json.load(open(CONFIG_PATH))
            cfg = DEFAULT_CFG.copy()
            cfg.update(c)
            return cfg
        except Exception as e:
            logger.warning(f"Config load error: {e}")
    return DEFAULT_CFG.copy()


def save_cfg(cfg):
    try:
        json.dump(cfg, open(CONFIG_PATH, "w"), indent=2)
    except Exception as e:
        logger.error(f"Config save error: {e}")


def os_notify(title, msg):
    """Silent OS notification - only for critical events."""
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["osascript", "-e",
                f'display notification "{msg}" with title "{title}"'], check=False)
        elif system == "Linux":
            subprocess.run(["notify-send", "-u", "critical", "-t", "6000", title, msg], check=False)
        elif system == "Windows":
            ps = (
                '[Windows.UI.Notifications.ToastNotificationManager,'
                'Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;'
                '$t=[Windows.UI.Notifications.ToastTemplateType]::ToastText02;'
                '$x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($t);'
                f'$x.GetElementsByTagName("text")[0].AppendChild($x.CreateTextNode("{title}"))|Out-Null;'
                f'$x.GetElementsByTagName("text")[1].AppendChild($x.CreateTextNode("{msg}"))|Out-Null;'
                '$n=[Windows.UI.Notifications.ToastNotification]::new($x);'
                '[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("SysGuard").Show($n)'
            )
            subprocess.run(["powershell", "-WindowStyle", "Hidden", "-Command", ps], check=False)
    except Exception:
        pass


def notification_worker(last_id_ref):
    """Background thread: watches DB for new CRITICAL events and fires OS notifications."""
    import sqlite3
    while True:
        try:
            conn = sqlite3.connect(db.DB_PATH, check_same_thread=False)
            rows = conn.execute(
                "SELECT id,category,severity,message FROM alerts "
                "WHERE id > ? AND severity = 'CRITICAL' ORDER BY id ASC LIMIT 5",
                (last_id_ref[0],)
            ).fetchall()
            conn.close()
            for row in rows:
                last_id_ref[0] = row[0]
                # Only notify on CRITICAL - silent otherwise
                os_notify(f"SysGuard {row[2]} — {row[1]}", row[3][:120])
        except Exception:
            pass
        time.sleep(5)


def db_maintenance():
    """Periodic database maintenance - trim old entries."""
    import sqlite3
    while True:
        time.sleep(300)  # Run every 5 minutes
        try:
            conn = sqlite3.connect(db.DB_PATH)
            # Keep only last 10,000 entries
            conn.execute("""
                DELETE FROM alerts WHERE id <= (
                    SELECT id FROM alerts ORDER BY id DESC LIMIT 10000 OFFSET 10000
                )
            """)
            conn.execute("VACUUM")  # Reclaim space
            conn.commit()
            conn.close()
            logger.debug("Database maintenance complete")
        except Exception as e:
            logger.warning(f"DB maintenance error: {e}")


class GracefulKiller:
    """Handle graceful shutdown on signals."""
    def __init__(self):
        self.kill_now = False
        signal.signal(signal.SIGINT, self._exit_gracefully)
        signal.signal(signal.SIGTERM, self._exit_gracefully)
    
    def _exit_gracefully(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.kill_now = True


def main():
    """Main entry point with crash handling."""
    killer = GracefulKiller()
    
    try:
        # Initialize database
        db.init_db()
        logger.info("SysGuard helper started")
        
        # Load configuration
        cfg = load_cfg()
        engine = MonitorEngine(cfg)
        
        # Get current max id for notifications
        import sqlite3
        conn = sqlite3.connect(db.DB_PATH)
        r = conn.execute("SELECT MAX(id) FROM alerts").fetchone()
        conn.close()
        last_id = [r[0] or 0]
        
        # Start notification watcher thread
        notif_thread = threading.Thread(
            target=notification_worker, 
            args=(last_id,), 
            daemon=True,
            name="SysGuard-Notif"
        )
        notif_thread.start()
        
        # Start database maintenance thread
        maint_thread = threading.Thread(
            target=db_maintenance,
            daemon=True,
            name="SysGuard-Maint"
        )
        maint_thread.start()
        
        # Start engine
        engine.start()
        
        # Main loop with config reload
        while not killer.kill_now:
            time.sleep(10)
            try:
                new_cfg = load_cfg()
                engine.update_config(new_cfg)
            except Exception as e:
                logger.warning(f"Config reload error: {e}")
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        # Try to log to file even on fatal error
        try:
            import sqlite3
            conn = sqlite3.connect(db.DB_PATH, check_same_thread=False)
            conn.execute(
                "INSERT INTO alerts (ts, category, severity, message) VALUES (?, ?, ?, ?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), "SYSTEM", "CRITICAL", f"Fatal error: {e}")
            )
            conn.commit()
            conn.close()
        except:
            pass
    finally:
        try:
            engine.stop()
        except:
            pass
        logger.info("SysGuard helper stopped")


if __name__ == "__main__":
    main()
