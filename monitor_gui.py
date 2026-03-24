"""
monitor_gui.py — Optimized SysGuard GUI
- All data from SQLite (db.py)
- Engine runs in daemon thread (never blocks UI)
- Silent logging - no popups or alert spam
- Memory optimized with bounded table displays
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os
import sys
import json
import platform
import subprocess
import queue

import db
from engine import MonitorEngine

# ── Config ────────────────────────────────────────────────────────────────────
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
DEFAULT_CONFIG = {
    "scan_interval": 8,
    "disk_write_threshold_mb": 50,
    "net_log_all": False,
    "suspicious_paths": ["appdata\\local\\temp", "\\temp\\", "/tmp/", "roaming"],
    "suspicious_ports": [4444, 5555, 6666, 1337, 9999, 31337],
    "alert_on_suspicious_net": True,
    "alert_on_high_disk": False,
    "startup_enabled": False,
}

MAX_TABLE_ROWS = 200  # Limit for memory optimization


def load_cfg():
    if os.path.exists(CONFIG_PATH):
        try:
            c = json.load(open(CONFIG_PATH))
            cfg = DEFAULT_CONFIG.copy()
            cfg.update(c)
            return cfg
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_cfg(cfg):
    json.dump(cfg, open(CONFIG_PATH, "w"), indent=2)


# ── Theme ─────────────────────────────────────────────────────────────────────
BG = "#0b0d12"
PANEL = "#10131c"
CARD = "#161b28"
BORDER = "#1e2638"
ACCENT = "#00c8ff"
GREEN = "#00e676"
YELLOW = "#ffca28"
RED = "#ff1744"
ORANGE = "#ff6d00"
MUTED = "#37415a"
TEXT = "#dde3f0"
SUB = "#6b7a99"

SEV_COL = {"INFO": GREEN, "WARN": YELLOW, "ALERT": ORANGE, "CRITICAL": RED}
CAT_ICON = {
    "SCREEN": "🖥", "MOUSE": "🖱", "PROCESS": "⚙", "NETWORK": "🌐",
    "DLL": "🔩", "DISK": "💾", "FILE": "📁", "CPU": "⚡",
    "INTEGRITY": "🔒", "SYSTEM": "ℹ",
}


# ── Alert Table Widget ────────────────────────────────────────────────────────
class AlertTable(tk.Frame):
    """Memory-optimized treeview-based alert table."""
    COLS = ("Time", "Sev", "Process", "PID", "Message")
    WIDTHS = (130, 70, 130, 60, 500)

    def __init__(self, parent, category_filter=None, severity_filter=None, **kw):
        super().__init__(parent, bg=BG, **kw)
        self.category_filter = category_filter
        self.severity_filter = severity_filter
        self._last_top_id = 0
        self._build()

    def _build(self):
        self.tree = ttk.Treeview(self, columns=self.COLS, show="headings",
                                  selectmode="browse")
        for col, w in zip(self.COLS, self.WIDTHS):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w", stretch=(col == "Message"))

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        for sev, col in SEV_COL.items():
            self.tree.tag_configure(sev, foreground=col)

    def refresh(self):
        """Pull latest rows - bounded for memory."""
        rows = db.fetch_alerts(
            category=self.category_filter,
            severity=self.severity_filter,
            limit=MAX_TABLE_ROWS
        )
        if not rows:
            return
        
        top_id = rows[0][0]
        if top_id <= self._last_top_id:
            return
        
        new_rows = [r for r in rows if r[0] > self._last_top_id]
        self._last_top_id = top_id

        for r in new_rows:
            rid, ts, cat, sev, pid, pname, msg, *_ = r
            icon = CAT_ICON.get(cat, "")
            self.tree.insert("", 0, iid=str(rid), tags=(sev,),
                values=(ts, f"{icon} {sev}", pname or "-", pid or "-", msg))

        # Cap rows for memory
        children = self.tree.get_children()
        if len(children) > MAX_TABLE_ROWS:
            for iid in children[MAX_TABLE_ROWS:]:
                self.tree.delete(iid)

    def full_reload(self):
        """Clear and reload."""
        self._last_top_id = 0
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.refresh()


# ── Main Application ─────────────────────────────────────────────────────────
class SysGuardApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg = load_cfg()

        db.init_db()
        self.engine = MonitorEngine(self.cfg)

        root.title("SysGuard — System Monitor")
        root.configure(bg=BG)
        root.geometry("1200x740")
        root.minsize(900, 580)

        self._setup_styles()
        self._build_ui()
        
        # Start engine and UI refresh loop
        self.engine.start()
        self._tick()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, fieldbackground=CARD,
                    bordercolor=BORDER, relief="flat", font=("Courier New", 9))
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=SUB,
                    padding=[18, 7], borderwidth=0, font=("Courier New", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", ACCENT)])
        s.configure("Treeview", background=CARD, fieldbackground=CARD,
                    foreground=TEXT, rowheight=22, font=("Courier New", 9), borderwidth=0)
        s.configure("Treeview.Heading", background=PANEL, foreground=SUB,
                    font=("Courier New", 9, "bold"), relief="flat")
        s.map("Treeview", background=[("selected", BORDER)])
        s.configure("TScrollbar", background=BORDER, troughcolor=BG,
                    borderwidth=0, relief="flat")
        s.configure("TCombobox", fieldbackground=CARD, background=CARD,
                    foreground=TEXT, selectbackground=BORDER)
        s.configure("TCheckbutton", background=BG, foreground=TEXT)

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg=PANEL, height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="◈ SYSGUARD", font=("Courier New", 15, "bold"),
                 bg=PANEL, fg=ACCENT).pack(side="left", padx=18)
        tk.Label(hdr, text="Silent System Monitor",
                 font=("Courier New", 9), bg=PANEL, fg=SUB).pack(side="left")
        self._dot = tk.Label(hdr, text="●", font=("Courier New", 13), bg=PANEL, fg=GREEN)
        self._dot.pack(side="right", padx=6)
        self._status_lbl = tk.Label(hdr, text="LIVE", font=("Courier New", 9, "bold"),
                                    bg=PANEL, fg=GREEN)
        self._status_lbl.pack(side="right", padx=2)

        # Stats strip
        self._stat_strip = tk.Frame(self.root, bg=PANEL, height=30)
        self._stat_strip.pack(fill="x")
        self._stat_strip.pack_propagate(False)
        self._stat_vars = {}
        for cat, col in [("SCREEN", RED), ("MOUSE", ORANGE), ("PROCESS", YELLOW),
                         ("NETWORK", ACCENT), ("DLL", "#c792ea"), ("TOTAL", TEXT)]:
            f = tk.Frame(self._stat_strip, bg=PANEL)
            f.pack(side="left", padx=14)
            tk.Label(f, text=cat, font=("Courier New", 7, "bold"),
                     bg=PANEL, fg=MUTED).pack(side="left")
            v = tk.StringVar(value=" 0")
            tk.Label(f, textvariable=v, font=("Courier New", 11, "bold"),
                     bg=PANEL, fg=col).pack(side="left")
            self._stat_vars[cat] = v

        # Notebook
        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill="both", expand=True)

        self._tabs: dict = {}
        self._build_screen_tab()
        self._build_mouse_tab()
        self._build_all_tab()
        self._build_process_tab()
        self._build_settings_tab()

        # Footer
        foot = tk.Frame(self.root, bg=PANEL, height=26)
        foot.pack(fill="x", side="bottom")
        foot.pack_propagate(False)
        self._footer = tk.Label(foot, text="Ready.", font=("Courier New", 8),
                                bg=PANEL, fg=SUB)
        self._footer.pack(side="left", padx=12)
        tk.Label(foot, text=f"{platform.system()} {platform.python_version()}",
                 font=("Courier New", 8), bg=PANEL, fg=MUTED).pack(side="right", padx=12)

    def _make_tab_frame(self, title):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text=f"  {title}  ")
        return frame

    def _build_screen_tab(self):
        frame = self._make_tab_frame("🖥  Screen Capture")
        top = tk.Frame(frame, bg=BG, pady=5)
        top.pack(fill="x", padx=8)
        tk.Button(top, text="🗑 Clear", font=("Courier New", 9),
                  bg=BORDER, fg=RED, bd=0, padx=8, pady=2, cursor="hand2",
                  command=lambda: self._clear("SCREEN")).pack(side="right", padx=4)
        tbl = AlertTable(frame, category_filter="SCREEN")
        tbl.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._tabs["SCREEN"] = tbl

    def _build_mouse_tab(self):
        frame = self._make_tab_frame("🖱  Mouse & Remote")
        top = tk.Frame(frame, bg=BG, pady=5)
        top.pack(fill="x", padx=8)
        tk.Button(top, text="🗑 Clear", font=("Courier New", 9),
                  bg=BORDER, fg=RED, bd=0, padx=8, pady=2, cursor="hand2",
                  command=lambda: self._clear("MOUSE")).pack(side="right", padx=4)
        tbl = AlertTable(frame, category_filter="MOUSE")
        tbl.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._tabs["MOUSE"] = tbl

    def _build_all_tab(self):
        frame = self._make_tab_frame("📋  All Alerts")
        top = tk.Frame(frame, bg=BG, pady=5)
        top.pack(fill="x", padx=8)

        cat_var = tk.StringVar(value="ALL")
        cat_cb = ttk.Combobox(top, textvariable=cat_var,
                              values=["ALL"] + db.CATEGORIES,
                              state="readonly", width=12)
        cat_cb.pack(side="left", padx=4)

        sev_var = tk.StringVar(value="ALL")
        sev_cb = ttk.Combobox(top, textvariable=sev_var,
                              values=["ALL"] + db.SEVERITIES,
                              state="readonly", width=10)
        sev_cb.pack(side="left", padx=4)

        tk.Button(top, text="🗑 Clear ALL", font=("Courier New", 9),
                  bg=BORDER, fg=RED, bd=0, padx=8, pady=2, cursor="hand2",
                  command=lambda: self._clear("ALL")).pack(side="right", padx=4)

        tbl = AlertTable(frame, category_filter=None, severity_filter=None)
        tbl.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._tabs["ALL"] = tbl

        def _refilter(*_):
            c = cat_var.get() if cat_var.get() != "ALL" else None
            s = sev_var.get() if sev_var.get() != "ALL" else None
            tbl.category_filter = c
            tbl.severity_filter = s
            tbl.full_reload()
        cat_var.trace_add("write", _refilter)
        sev_var.trace_add("write", _refilter)

    def _build_process_tab(self):
        frame = self._make_tab_frame("⚙  Processes")
        cols = ("PID", "Name", "CPU%", "Mem MB", "Status", "EXE")
        self._proc_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, w in zip(cols, [60, 170, 60, 80, 80, 400]):
            self._proc_tree.heading(col, text=col)
            self._proc_tree.column(col, width=w, anchor="w")
        self._proc_tree.tag_configure("sus", foreground=RED)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._proc_tree.yview)
        self._proc_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._proc_tree.pack(fill="both", expand=True, padx=8, pady=8)
        btn = tk.Frame(frame, bg=BG, pady=4)
        btn.pack(fill="x", padx=8)
        tk.Button(btn, text="⟳ Refresh", font=("Courier New", 9),
                  bg=BORDER, fg=ACCENT, bd=0, padx=8, pady=2, cursor="hand2",
                  command=self._refresh_procs).pack(side="left")
        self._nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

    def _build_settings_tab(self):
        frame = self._make_tab_frame("⚙  Settings")
        canvas = tk.Canvas(frame, bg=BG, bd=0, highlightthickness=0)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG)
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(wid, width=e.width))

        def sec(text, color=ACCENT):
            tk.Label(inner, text=text, font=("Courier New", 11, "bold"),
                     bg=BG, fg=color).pack(anchor="w", padx=20, pady=(18, 2))
            tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", padx=20, pady=(0, 6))

        def row(label):
            f = tk.Frame(inner, bg=BG)
            f.pack(fill="x", padx=20, pady=3)
            tk.Label(f, text=label, font=("Courier New", 9), width=30,
                     bg=BG, fg=TEXT, anchor="w").pack(side="left")
            return f

        sec("⏱  Scanning")
        self._v_interval = tk.IntVar(value=self.cfg["scan_interval"])
        f = row("Scan interval (seconds)")
        tk.Scale(f, variable=self._v_interval, from_=3, to=60, orient="horizontal",
                 length=180, bg=BG, fg=TEXT, troughcolor=BORDER,
                 highlightthickness=0).pack(side="left")
        tk.Label(f, textvariable=self._v_interval, font=("Courier New", 9),
                 bg=BG, fg=ACCENT, width=3).pack(side="left")

        sec("🔔  Alerts")
        self._v_alerts = {}
        for key, label in [
            ("alert_on_suspicious_net", "Alert on suspicious network"),
            ("alert_on_high_disk", "Alert on high disk writes"),
        ]:
            v = tk.BooleanVar(value=self.cfg.get(key, True))
            self._v_alerts[key] = v
            f = row(label)
            tk.Checkbutton(f, variable=v, bg=BG, fg=TEXT,
                           selectcolor=CARD, activebackground=BG).pack(side="left")

        sec("🔌  Suspicious ports")
        self._v_ports = tk.StringVar(value=", ".join(map(str, self.cfg["suspicious_ports"])))
        tk.Entry(inner, textvariable=self._v_ports, font=("Courier New", 9),
                 bg=CARD, fg=TEXT, insertbackground=ACCENT, bd=0, relief="flat",
                 width=60).pack(anchor="w", padx=20, pady=4)

        tk.Frame(inner, bg=BG, height=10).pack()
        tk.Button(inner, text="  💾  SAVE  ",
                  font=("Courier New", 10, "bold"),
                  bg=ACCENT, fg=BG, bd=0, relief="flat", padx=12, pady=6,
                  cursor="hand2", command=self._save_settings).pack(padx=20, pady=8)
        tk.Frame(inner, bg=BG, height=30).pack()

    def _tick(self):
        """UI refresh loop - runs on main thread."""
        try:
            for tbl in self._tabs.values():
                tbl.refresh()
            self._update_stats()
            
            alive = self.engine.is_running()
            self._dot.config(fg=GREEN if alive else RED)
            self._status_lbl.config(text="LIVE" if alive else "STOPPED",
                                    fg=GREEN if alive else RED)
        except Exception:
            pass
        self.root.after(2000, self._tick)

    def _update_stats(self):
        counts = db.count_by_category()
        total = db.total_count()
        for cat, var in self._stat_vars.items():
            if cat == "TOTAL":
                var.set(f" {total}")
            else:
                var.set(f" {counts.get(cat, 0)}")
        recent = db.get_recent(1)
        if recent:
            r = recent[0]
            self._footer.config(
                text=f"Last: [{r[2]}] [{r[3]}] {r[6][:90]}",
                fg=SEV_COL.get(r[3], TEXT)
            )

    def _clear(self, category):
        if not messagebox.askyesno("Clear", f"Clear {category} alerts?"):
            return
        db.clear_category(category)
        for tbl in self._tabs.values():
            tbl.full_reload()

    def _on_tab_change(self, event):
        idx = self._nb.index("current")
        if idx == 3:
            self._refresh_procs()

    def _refresh_procs(self):
        try:
            import psutil
        except ImportError:
            return
        for row in self._proc_tree.get_children():
            self._proc_tree.delete(row)
        
        from engine import SCREEN_PROC_KEYWORDS, MOUSE_PROC_KEYWORDS
        all_kw = set(SCREEN_PROC_KEYWORDS) | set(MOUSE_PROC_KEYWORDS)
        
        for proc in psutil.process_iter(["pid", "name", "exe", "status"]):
            try:
                p = proc.info
                cpu = proc.cpu_percent(interval=None)
                mem = proc.memory_info().rss / (1024 * 1024)
                exe = p.get("exe") or ""
                name = (p.get("name") or "").lower()
                sus = any(k in name or k in exe.lower() for k in all_kw)
                self._proc_tree.insert("", "end", tags=("sus" if sus else "",),
                    values=(p["pid"], p["name"] or "?", f"{cpu:.1f}",
                            f"{mem:.1f}", p["status"] or "?", exe))
            except Exception:
                continue

    def _save_settings(self):
        try:
            ports = [int(p.strip()) for p in self._v_ports.get().split(",") if p.strip()]
        except ValueError:
            messagebox.showerror("Error", "Ports must be comma-separated integers.")
            return
        self.cfg["scan_interval"] = self._v_interval.get()
        self.cfg["suspicious_ports"] = ports
        for k, v in self._v_alerts.items():
            self.cfg[k] = v.get()
        save_cfg(self.cfg)
        self.engine.update_config(self.cfg)
        messagebox.showinfo("Saved", "Settings saved.")


def main():
    root = tk.Tk()
    try:
        root.iconbitmap(default="")
    except Exception:
        pass
    app = SysGuardApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.engine.stop(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
