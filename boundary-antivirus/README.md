# Boundary Antivirus

Standalone malware detection engine extracted from [Boundary Daemon](https://github.com/kase1111-hash/boundary-daemon).

Provides keylogger detection, screen capture malware detection, clipboard hijacker detection, process monitoring, and real-time file system surveillance.

## Installation

```bash
pip install boundary-antivirus
```

## Usage

```python
from boundary_antivirus import AntivirusScanner

scanner = AntivirusScanner()
results = scanner.full_scan()
```

## GUI

```bash
python -m boundary_antivirus.gui
```

## Origin

This package was extracted from the Boundary Daemon security module to operate as an independent project. The original code lived at `daemon/security/antivirus.py` and `daemon/security/antivirus_gui.py`.
