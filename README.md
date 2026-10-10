# Windows System & Security Monitor

Live Windows monitoring toolkit that reads processes, resources, services,
Registry and Event Viewer in real time, with a Streamlit dashboard for visualization.

## Features

1. System and process inventory — names, PIDs, executable paths, command lines,
   parent PID and name.
2. Real-time resource usage — per-process CPU %, RAM, disk I/O rates, open
   sockets plus total up and down throughput.
3. System performance summary — total and per-core CPU, RAM total, used and
   available, page file (swap) usage.
4. Services and startup audit — Windows service states and auto-start entries
   from Registry Run and RunOnce keys.
5. Security auditing — logons and logoffs (4624, 4634), failed logons (4625),
   account creation and privilege escalation (4720, 4728), app crashes and
   unexpected shutdowns (1000, 6008), installed-software blocklist check, USB
   history plus currently connected USB devices.

## Installation

Requires Windows 10 or 11, Python 3.10+, and Git.

```bash
git clone https://github.com/Riann121/Windows-System-Security-Monitor.git
cd Windows-System-Security-Monitor
```

Install dependencies:

```bash
pip install --upgrade pip
pip install psutil streamlit pandas
```
