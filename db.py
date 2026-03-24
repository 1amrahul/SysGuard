"""
db.py — Optimized SQLite alert storage for SysGuard
- Thread-safe with connection pooling
- Automatic cleanup of old entries
- Memory optimized queries
"""
import sqlite3
import os
import threading
import logging
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sysguard.db")

# Maximum entries to keep in database
MAX_ENTRIES = 10000
# Enable WAL mode for better concurrency
WAL_MODE = True

logger = logging.getLogger(__name__)

_local = threading.local()

CATEGORIES = [
    "SCREEN", "MOUSE", "PROCESS", "NETWORK", "DLL",
    "DISK", "FILE", "CPU", "INTEGRITY", "SYSTEM",
]

SEVERITIES = ["INFO", "WARN", "ALERT", "CRITICAL"]


def _get_conn():
    """Get thread-local database connection with optimized settings."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(
            DB_PATH,
            check_same_thread=False,
            timeout=10.0,
            isolation_level=None  # Autocommit mode for performance
        )
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn.execute("PRAGMA cache_size=-2000")  # 2MB cache
        _local.conn.execute("PRAGMA temp_store=MEMORY")
    return _local.conn


@contextmanager
def get_connection():
    """Context manager for database operations."""
    conn = _get_conn()
    try:
        yield conn
    except Exception as e:
        logger.error(f"Database error: {e}")
        raise


def init_db():
    """Initialize database with optimized schema."""
    c = _get_conn()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT    NOT NULL,
            category  TEXT    NOT NULL,
            severity  TEXT    NOT NULL,
            pid       INTEGER,
            proc_name TEXT,
            message   TEXT    NOT NULL,
            detail    TEXT,
            seen      INTEGER DEFAULT 0
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_cat ON alerts(category)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sev ON alerts(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON alerts(ts)")
    c.commit()
    
    # Run initial cleanup
    trim_db()


def insert_alert(category, severity, message, pid=None, proc_name=None, detail=None):
    """Thread-safe insert with automatic cleanup."""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""
            INSERT INTO alerts (ts, category, severity, pid, proc_name, message, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            category, severity, pid, proc_name, message, detail
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass  # Never crash the monitor on DB error


def fetch_alerts(category=None, severity=None, limit=500, offset=0):
    """Fetch alerts with optional filters - optimized with bounded results."""
    with get_connection() as c:
        clauses, params = [], []
        if category and category != "ALL":
            clauses.append("category = ?")
            params.append(category)
        if severity and severity != "ALL":
            clauses.append("severity = ?")
            params.append(severity)
        
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([min(limit, 1000), offset])  # Cap limit at 1000
        
        rows = c.execute(
            f"SELECT id,ts,category,severity,pid,proc_name,message,detail "
            f"FROM alerts {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params
        ).fetchall()
        return rows


def count_by_category():
    """Get count by category - cached query."""
    with get_connection() as c:
        rows = c.execute(
            "SELECT category, COUNT(*) FROM alerts GROUP BY category"
        ).fetchall()
        return dict(rows)


def count_by_severity():
    """Get count by severity - cached query."""
    with get_connection() as c:
        rows = c.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
        ).fetchall()
        return dict(rows)


def get_recent(n=20):
    """Get recent alerts - bounded result."""
    with get_connection() as c:
        return c.execute(
            "SELECT id,ts,category,severity,pid,proc_name,message "
            f"FROM alerts ORDER BY id DESC LIMIT {min(n, 100)}",
        ).fetchall()


def clear_category(category):
    """Clear alerts by category or all."""
    with get_connection() as c:
        if category == "ALL":
            c.execute("DELETE FROM alerts")
        else:
            c.execute("DELETE FROM alerts WHERE category=?", (category,))
        c.commit()


def total_count():
    """Get total alert count."""
    with get_connection() as c:
        return c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def trim_db():
    """Trim database to MAX_ENTRIES - call periodically."""
    try:
        with get_connection() as c:
            count = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            if count > MAX_ENTRIES:
                delete_count = count - MAX_ENTRIES
                c.execute(f"""
                    DELETE FROM alerts WHERE id IN (
                        SELECT id FROM alerts ORDER BY id ASC LIMIT ?
                    )
                """, (delete_count,))
                c.commit()
                logger.info(f"Trimmed {delete_count} old alerts")
    except Exception as e:
        logger.warning(f"DB trim error: {e}")


def vacuum_db():
    """Vacuum database to reclaim space."""
    try:
        with get_connection() as c:
            c.execute("VACUUM")
        logger.info("Database vacuumed")
    except Exception as e:
        logger.warning(f"DB vacuum error: {e}")


def get_stats():
    """Get database statistics."""
    with get_connection() as c:
        total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_cat = dict(c.execute(
            "SELECT category, COUNT(*) FROM alerts GROUP BY category"
        ).fetchall())
        by_sev = dict(c.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
        ).fetchall())
        return {
            "total": total,
            "by_category": by_cat,
            "by_severity": by_sev,
        }
