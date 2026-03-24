# SysGuard - Silent System Monitor

A cross-platform security monitoring tool that silently detects screen capture, mouse/keyboard hooks, and suspicious processes. Runs in the background with minimal resource usage.

## Features

- **Screen Capture Detection** - Detects OBS, ShareX, Fraps, and other screen capture tools
- **Mouse/Remote Monitoring** - Detects TeamViewer, VNC, AnyDesk, keyloggers
- **Process Integrity** - Monitors for binary tampering and suspicious spawns
- **Network Monitoring** - Alerts on suspicious ports and connections
- **Behavior-Based Detection** - Advanced heuristics for custom monitoring tools:
  - Outbound data volume anomaly detection
  - Parent process chain analysis
  - GDI handle count monitoring
  - ETW Win32k screen API detection

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sysguard.git
cd sysguard

# Install dependencies
pip install psutil

# Run the GUI
python launcher.py

# Or run headless
python launcher.py --helper
```

## Usage

### GUI Mode
```bash
python launcher.py
```

### Headless Mode (Background Service)
```bash
python launcher.py --helper
```

### Auto-start on Boot
```bash
# Enable
python launcher.py --startup

# Disable
python launcher.py --no-startup
```

## Configuration

Edit `config.json` to customize:

```json
{
    "scan_interval": 8,
    "disk_write_threshold_mb": 50,
    "suspicious_ports": [4444, 5555, 6666, 1337, 9999, 31337],
    "suspicious_paths": ["appdata\\local\\temp", "\\temp\\", "/tmp/"],
    "alert_on_suspicious_net": true,
    "alert_on_high_disk": false
}
```

## Requirements

- Python 3.8+
- psutil

## Platform Support

- Windows (primary)
- macOS
- Linux

## License

MIT License - see LICENSE file

## Disclaimer

This tool is for educational and defensive purposes only. Always use responsibly and in compliance with applicable laws and regulations.
