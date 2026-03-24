"""
launcher.py — SysGuard entry point.
Usage:
  python launcher.py           → GUI
  python launcher.py --helper  → headless background monitor
  python launcher.py --startup → register auto-start
"""
import sys
import os
import subprocess
import platform
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def install_deps():
    """Install required dependencies."""
    required = ["psutil"]
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            print(f"Installing {pkg}...")
            flags = ["--break-system-packages"] if platform.system() == "Linux" else []
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg] + flags)


def setup_startup(enable):
    """Configure auto-start on system boot."""
    exe = sys.executable
    script = os.path.join(SCRIPT_DIR, "helper_process.py")
    system = platform.system()
    
    try:
        if system == "Windows":
            import winreg
            key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE)
            if enable:
                winreg.SetValueEx(reg, "SysGuard", 0, winreg.REG_SZ, f'"{exe}" "{script}"')
                print("✓ Windows startup enabled")
            else:
                try:
                    winreg.DeleteValue(reg, "SysGuard")
                except FileNotFoundError:
                    pass
                print("✓ Windows startup disabled")
            winreg.CloseKey(reg)
            
        elif system == "Darwin":
            from pathlib import Path
            plist = Path("~/Library/LaunchAgents/com.sysguard.helper.plist").expanduser()
            if enable:
                plist.write_text(f"""<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.sysguard.helper</string>
  <key>ProgramArguments</key><array>
    <string>{exe}</string><string>{script}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>""")
                subprocess.run(["launchctl", "load", str(plist)], check=False)
                print(f"✓ macOS LaunchAgent installed: {plist}")
            else:
                if plist.exists():
                    subprocess.run(["launchctl", "unload", str(plist)], check=False)
                    plist.unlink()
                    print("✓ macOS LaunchAgent removed")
                    
        elif system == "Linux":
            from pathlib import Path
            d = Path("~/.config/autostart").expanduser()
            d.mkdir(parents=True, exist_ok=True)
            f = d / "sysguard.desktop"
            if enable:
                f.write_text(f"[Desktop Entry]\nType=Application\nName=SysGuard\nExec={exe} {script}\nX-GNOME-Autostart-enabled=true\n")
                print(f"✓ Linux autostart: {f}")
            else:
                if f.exists():
                    f.unlink()
                    print("✓ Linux autostart removed")
    except Exception as e:
        print(f"Startup config error: {e}")


def main():
    parser = argparse.ArgumentParser(description="SysGuard Monitor")
    parser.add_argument("--helper", action="store_true", help="Run headless helper")
    parser.add_argument("--startup", action="store_true", help="Enable boot auto-start")
    parser.add_argument("--no-startup", action="store_true", help="Disable boot auto-start")
    args = parser.parse_args()

    install_deps()

    if args.startup:
        setup_startup(True)
        return
    if args.no_startup:
        setup_startup(False)
        return

    # Add script dir to path
    sys.path.insert(0, SCRIPT_DIR)

    if args.helper:
        import helper_process
        helper_process.main()
    else:
        import monitor_gui
        monitor_gui.main()


if __name__ == "__main__":
    main()
