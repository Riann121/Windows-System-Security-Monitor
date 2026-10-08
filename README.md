# Windows System & Security Monitor

Live Windows monitoring toolkit: a Python collector layer that reads
processes, resources, services, Registry and Event Viewer in real time,
plus a single-page Streamlit dashboard for visualization.

Built from `task_manager_and_security_features_list.txt`. See `workflow.md`
for the full data-flow description.

## Features

1. **System & process inventory** — names, PIDs, executable paths,
   command lines, parent PID/name for every live process.
2. **Real-time resource usage** — per-process CPU %, RAM, disk I/O rates,
   open sockets plus total up/down throughput.
3. **System performance summary** — total and per-core CPU, RAM
   total/used/available, page file (swap) usage.
4. **Services & startup audit** — Windows service states and auto-start
   entries from the Registry `Run`/`RunOnce` keys via `reg query`.
5. **Security auditing** — logons/logoffs (4624/4634), failed logons (4625),
   account creation and privilege escalation (4720/4728), app crashes and
   unexpected shutdowns (1000/6008) via `wevtutil`, installed-software
   blocklist check via Registry, USB history traces plus **currently
   connected** USB/removable devices with drive letters and free space.

## Architecture

```text
system_security_monitor.py   live collectors, return plain dicts/lists
        |  psutil (processes, CPU, RAM, disk, network)
        |  reg query (startup, installed software, USBSTOR history)
        |  wevtutil (Security / System / Application event logs)
        v
dashboard_app.py             Streamlit UI only, no Windows calls in render
        |  live_snapshot.json  full snapshot, remade each refresh
        |  usb_live.json       USB-only file, remade every 2 s by watcher
        |  dashboard_history.csv  one row per refresh for time-range charts
```

Design rules: collectors never draw UI; the dashboard renders from files,
so old data stays visible until new data is ready (stale-while-revalidate).

## Project structure

```text
week5/
  system_security_monitor.py  collectors + terminal infinite-loop monitor
  dashboard_app.py            single-page Streamlit dashboard
  task_manager_and_security_features_list.txt  original feature spec
  workflow.md                 data sources, workflow, run instructions
  1_vwNs9W7rzUdXEnOmqivb4w.webp  dashboard layout reference image
  .gitignore                  excludes live JSON/CSV and cache files
```

Generated at runtime and intentionally untracked:
`live_snapshot.json`, `usb_live.json`, `dashboard_history.csv`.

## Requirements

- Windows 10/11, Python 3.10+
- `pip install psutil streamlit pandas` (Altair ships with Streamlit)
- Administrator terminal recommended for the Security event log
  (IDs 4624/4625/4720/4728); everything else works as a normal user.

## Usage

Terminal live monitor (infinite loop, Ctrl+C stops):

```bash
cd week5
python system_security_monitor.py                 # refresh every 5 s
python system_security_monitor.py --once          # single snapshot
python system_security_monitor.py --interval 10   # custom interval
```

Streamlit dashboard:

```bash
cd week5
streamlit run dashboard_app.py
```

## Dashboard guide

- **Single page, no navigation.** Metrics row, CPU/RAM top-process bars,
  failed-logon and CPU/RAM history lines, security findings
  (blocklist, USB, crashes), then live detail tables.
- **Top bar is red.** In each performance bar chart the highest consumer
  renders in red; the rest use muted blue. Blocklisted app names render
  as red text.
- **Time ranges.** Sidebar selector (last hour, 24 hours, 7 days, 30 days)
  filters every time-based chart from the history file. History accumulates
  one row per refresh, so long ranges fill in over time.
- **Live updates.** A background thread rewrites `usb_live.json` every
  2 seconds (adaptive sleep keeps the true period at ~2 s). The full
  snapshot is slower (~20 s: CPU sampling plus software scan) and swaps in
  only when ready — the screen never blanks.
- **Corner clock.** Fixed top-right badge shows `Updated <full> | USB <2s>`,
  proving which cycle each panel came from. The USB card header repeats its
  own refresh timestamp.
- **USB card.** Two sections: currently connected devices (model, drive
  letters, volume label, filesystem, size, free space) and ever-plugged-in
  history traces from USBSTOR.

## Color theme

Soft dark slate background with muted blue/green charts for comfortable
long viewing sessions. Red is reserved exclusively for the top resource
consumer, failed-logon trend, and policy violations.

## Known limitations

- Per-process exact bandwidth in KB/s requires a packet driver; the tool
  reports per-process open sockets plus total NIC throughput instead.
- `System Idle Process` CPU can exceed 100% (summed across cores);
  this is genuine Windows behavior.
- Without Admin rights the Security log queries return empty and the
  failed-logon chart shows a guidance notice.
- A full refresh takes ~20 s (13 s process sampling, 7 s software scan,
  2 s services); only the USB path meets the 2-second cadence by design.
