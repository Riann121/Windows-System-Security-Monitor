# Windows System & Security Monitoring Tool
# ==========================================
# Beginner-friendly live monitor for Windows.
#
# Covers ALL features from task_manager_and_security_features_list.txt:
#
#   1. System & Process Inventory   (names, PIDs, paths, cmdline, parents)
#   2. Real-Time Resource Usage     (CPU %, RAM, Disk I/O, Network)
#   3. System Performance Summary   (total CPU, RAM, Swap/Pagefile)
#   4. Services & Startup Programs  (services + Registry Run keys)
#   5. Registry & Event Viewer Audit (logons, failed logins, software
#      blocklist, account changes, USB, crashes/hangs)
#
# HOW DATA STAYS "LIVE":
#   Every function queries Windows RIGHT NOW when you call it.
#   - Processes / CPU / RAM / Disk / Network -> `psutil` library (live)
#   - Startup apps / Installed software / USB -> `reg query` command (live Registry)
#   - Logons / failures / crashes -> `wevtutil` command (live Event Viewer)
#   Nothing is saved to a file. Call the function again = fresh data.
#
# STREAMLIT NOTE (for later):
#   All functions below RETURN plain Python data (list / dict).
#   They do NOT draw any UI. That is on purpose.
#   Later, a Streamlit dashboard can simply do:
#       import system_security_monitor as mon
#       st.dataframe(mon.get_process_inventory())
#   See the commented example at the very bottom of this file.
#
# Run this file directly to test:
#     python system_security_monitor.py               -> runs forever, refresh every 5 sec
#     python system_security_monitor.py --once        -> runs one time and stops
#     python system_security_monitor.py --interval 10 -> runs forever, refresh every 10 sec
# Press Ctrl+C to stop the infinite loop.

# ---------------------------------------------------------------------------
# STEP 0: Imports
# ---------------------------------------------------------------------------
# psutil      = reads live processes, CPU, RAM, disk, network
# subprocess  = lets Python run Windows commands like `reg query` and `wevtutil`
# datetime    = for timestamps
# ---------------------------------------------------------------------------

import subprocess
import psutil
import datetime
import time
import os
import sys


# ---------------------------------------------------------------------------
# STEP 1: Settings you can change (Configuration)
# ---------------------------------------------------------------------------

# Software that is NOT allowed on this computer.
# We compare installed programs (from Registry) against this list.
BLOCKLISTED_APPS = [
    "utorrent",
    "bittorrent",
    "anydesk",
    "teamviewer",
    "crack",
    "keygen",
]

# Event Viewer IDs we care about (Security log + System/Application logs).
# You can look these up in Windows Event Viewer yourself.
EVENT_IDS = {
    "successful_logon": 4624,      # someone logged in OK
    "logoff": 4634,                # someone logged off
    "failed_logon": 4625,          # wrong password / intrusion attempt
    "account_created": 4720,       # new user created
    "added_to_group": 4728,        # user given extra privilege (admin etc.)
    "app_crash": 1000,             # application hang/crash (Application log)
    "unexpected_shutdown": 6008,   # dirty shutdown / crash (System log)
}

# Registry paths we check with `reg query`.
# These are the official auto-start locations Windows uses.
REG_STARTUP_PATHS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]

# Registry paths where installed programs are listed.
REG_UNINSTALL_PATHS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]

# Registry path where USB storage devices leave traces.
REG_USB_PATH = r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"

# How many seconds to wait between live refreshes in infinite-loop mode.
# Change this one number to make the monitor faster or slower.
REFRESH_SECONDS = 5


# ---------------------------------------------------------------------------
# STEP 2: Small helper tools (used by many functions below)
# ---------------------------------------------------------------------------

def run_command(command_list):
    #     Run any Windows command and return its text output.
    #
    #     Example:
    #         run_command(["reg", "query", "HKLM\\SOFTWARE\\..."])
    #         run_command(["wevtutil", "qe", "Security", "/c:5", "/f:text"])
    #
    #     Returns empty string "" if the command fails (e.g. need Admin rights).
    #     We never crash here -- we just return "" so beginners see no traceback.
    #
    try:
        result = subprocess.run(
            command_list,
            capture_output=True,   # grab output instead of printing it
            text=True,             # give us string, not bytes
            timeout=30,            # stop if Windows hangs for 30 sec
        )
        return result.stdout
    except Exception as e:
        print(f"[Warning] Command failed {' '.join(command_list)}: {e}")
        return ""


def run_reg_query(registry_path):
    #     Run:  reg query <registry_path>
    #     Returns the raw text Windows gives back.
    #
    #     Why `reg query`?
    #       The task file says: 'Scan Registry paths...' and
    #       'Compare installed software ... via Registry queries.'
    #       So we use the real Windows tool, not a Python shortcut.
    #
    return run_command(["reg", "query", registry_path])


def run_wevtutil_query(log_name, event_id, count=20):
    #     Read LIVE logs from Windows Event Viewer using `wevtutil`.
    #
    #     This runs something like:
    #       wevtutil qe Security /q:*[System[(EventID=4624)]] /f:text /c:20
    #
    #     log_name : "Security", "System", or "Application"
    #     event_id : number like 4624, 4625, 6008, 1000
    #     count    : how many newest events to fetch (live data)
    #
    #     Returns raw text. Each event block is separated by blank lines.
    #
    # XPath query: this is the filter language Event Viewer understands.
    xpath = f"*[System[(EventID={event_id})]]"
    command = [
        "wevtutil", "qe", log_name,
        f"/q:{xpath}",
        "/f:text",          # human-readable text (easier for beginners)
        f"/c:{count}",      # how many events
        "/rd:true",         # newest first (reverse direction)
    ]
    return run_command(command)


def parse_wevtutil_text(raw_text):
    #     Turn the big text from `wevtutil` into a clean Python list.
    #
    #     Each event becomes a dict like:
    #         {"Date": "...", "Event ID": "4625", "Description": "...", "raw": "..."}
    #
    #     This is intentionally simple so beginners can read it.
    #
    events = []
    if not raw_text.strip():
        return events

    # wevtutil /f:text separates events with a line of **** or blank lines.
    # Simplest reliable split: split on "Event[" which starts each block.
    # If format changes, we still keep the raw block so nothing is lost.
    blocks = raw_text.split("Event[")
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        full_block = "Event[" + block

        # Pick out a few useful lines for quick display.
        info = {"raw": full_block}
        for line in full_block.splitlines():
            line = line.strip()
            # Typical lines look like: "Date: 2024-05-01T10:00:00.000"
            if line.startswith("Date:"):
                info["Date"] = line.replace("Date:", "").strip()
            elif line.startswith("Event ID:"):
                info["Event ID"] = line.replace("Event ID:", "").strip()
            elif line.startswith("Description:"):
                info["Description"] = line.replace("Description:", "").strip()

        events.append(info)

    return events


    # ===========================================================================
    # FEATURE 1: SYSTEM & PROCESS INVENTORY (live via psutil)
    # ===========================================================================

def get_process_inventory(limit=None):
    #     List every running process RIGHT NOW with:
    #       - Process Name & PID
    #       - Executable Path (e.g. C:\\Program Files\\...)
    #       - Command-Line Arguments (how it was launched)
    #       - Parent PID & Parent Name (who started it?)
    #
    #     limit: set to a number like 50 to only return first 50 rows (for testing).
    #
    #     Returns: list of dicts. Streamlit can show it with st.dataframe().
    #
    inventory = []

    # psutil.process_iter asks Windows for the live process table.
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            data = proc.info  # dict with pid, name, exe, cmdline, ppid

            # Find the parent's name (beginner-friendly: who launched this?)
            parent_name = ""
            try:
                parent = psutil.Process(data["ppid"])
                parent_name = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_name = "Unknown"

            inventory.append({
                "pid": data["pid"],
                "name": data["name"] or "Unknown",
                "exe_path": data["exe"] or "Access Denied",
                # cmdline is a list like ["chrome.exe", "--flag"]; join to string
                "cmdline": " ".join(data["cmdline"]) if data["cmdline"] else "",
                "parent_pid": data["ppid"],
                "parent_name": parent_name,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process closed while we were reading, or no permission. Skip it.
            continue

    if limit is not None:
        inventory = inventory[:limit]

    return inventory


    # ===========================================================================
    # FEATURE 2: REAL-TIME RESOURCE USAGE (live via psutil)
    # ===========================================================================

def get_process_resource_usage(limit=None):
    #     Live CPU %, RAM, and Disk I/O speed for each process.
    #
    #     NOTE on Disk I/O rates:
    #       psutil gives TOTAL bytes read/written since process started.
    #       True "KB/s" needs two measurements. We do that here:
    #       measure -> wait 1 second -> measure again -> difference = per-second rate.
    #
    #     Returns: list of dicts with keys:
    #       pid, name, cpu_percent, memory_mb, disk_read_kbs, disk_write_kbs
    #
    # STEP A: "prime" the CPU counter for every process.
    # Beginner note: Windows calculates CPU % as (work done / time passed).
    # The FIRST call always returns 0.0 -- it just starts the stopwatch.
    # The SECOND call (after 1 second) gives the real number.
    procs = list(psutil.process_iter(["pid", "name", "memory_info"]))
    for proc in procs:
        try:
            proc.cpu_percent(interval=None)  # 1st call = start stopwatch
            try:
                proc.io_counters()  # touch IO so it is cached
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # First snapshot of disk counters (total bytes so far).
    first_snapshot = {}
    for proc in procs:
        try:
            io = proc.io_counters()  # total read/write bytes
            first_snapshot[proc.info["pid"]] = (proc.info["name"], io.read_bytes, io.write_bytes)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Wait 1 second. During this second Windows counts CPU + disk activity.
    # This ONE wait serves both CPU % and Disk KB/s calculations.
    import time
    time.sleep(1.0)

    # STEP B: second reading = real live values.
    results = []
    for proc in procs:
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or "Unknown"

            # Live CPU % for THIS process (non-blocking, uses last interval).
            cpu = proc.cpu_percent(interval=0.0)

            # Live RAM in MB (RSS = physical RAM actually in use).
            ram_mb = round(proc.info["memory_info"].rss / (1024 * 1024), 2)

            # Disk speed = (now - 1 second ago) converted to KB/s.
            read_kbs = 0.0
            write_kbs = 0.0
            try:
                io_now = proc.io_counters()
                if pid in first_snapshot:
                    _, old_read, old_write = first_snapshot[pid]
                    read_kbs = round((io_now.read_bytes - old_read) / 1024, 2)
                    write_kbs = round((io_now.write_bytes - old_write) / 1024, 2)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            results.append({
                "pid": pid,
                "name": name,
                "cpu_percent": cpu,
                "memory_mb": ram_mb,
                "disk_read_kbs": max(read_kbs, 0.0),
                "disk_write_kbs": max(write_kbs, 0.0),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Most interesting first: highest CPU at top.
    results.sort(key=lambda x: x["cpu_percent"], reverse=True)

    if limit is not None:
        results = results[:limit]

    return results


def get_network_usage_per_process():
    #     Show which processes RIGHT NOW have open network connections,
    #     and the total system network speed (sent/received KB/s).
    #
    #     Beginner note:
    #       Per-process exact "bandwidth KB/s" needs a packet driver (like WinPcap).
    #       Without extra drivers, the honest live data Windows gives us is:
    #         1) every open socket per process (IP + port + status)
    #         2) total system NIC speed (live, measured over 1 second)
    #       That is what this function returns. It is 100% live.
    #
    # --- Part A: live open connections per process ---
    connections = psutil.net_connections(kind="inet")
    per_process = {}  # pid -> list of "192.168.1.5:443 (ESTABLISHED)"

    for conn in connections:
        pid = conn.pid
        if pid is None:
            continue  # some system connections have no owner
        try:
            label = f"{conn.laddr.ip}:{conn.laddr.port} -> "
            if conn.raddr:
                label += f"{conn.raddr.ip}:{conn.raddr.port}"
            else:
                label += "listening"
            label += f" ({conn.status})"
        except Exception:
            label = str(conn.status)

        per_process.setdefault(pid, []).append(label)

    # --- Part B: live total network speed (KB/s) ---
    io1 = psutil.net_io_counters()
    import time
    time.sleep(1)  # wait 1 second so we can compute "per second"
    io2 = psutil.net_io_counters()

    sent_kbs = round((io2.bytes_sent - io1.bytes_sent) / 1024, 2)
    recv_kbs = round((io2.bytes_recv - io1.bytes_recv) / 1024, 2)

    rows = []
    for pid, sock_list in per_process.items():
        try:
            name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "Unknown"
        rows.append({
            "pid": pid,
            "name": name,
            "open_connections": len(sock_list),
            "sockets": sock_list[:5],  # first 5 only, to keep it readable
        })

    # Highest connection count first.
    rows.sort(key=lambda x: x["open_connections"], reverse=True)

    return {
        "system_sent_kbs": sent_kbs,      # live upload speed
        "system_recv_kbs": recv_kbs,      # live download speed
        "per_process": rows,              # live socket table
    }


    # ===========================================================================
    # FEATURE 3: SYSTEM PERFORMANCE SUMMARY (live via psutil)
    # ===========================================================================

def get_system_summary():
    #     Overall machine health RIGHT NOW:
    #       - Total CPU load % + per-core breakdown
    #       - Total / Used / Available RAM
    #       - Page File / Swap usage % (virtual memory)
    #
    #     Returns one dict. Perfect for Streamlit metrics (st.metric).
    #
    # interval=1 makes cpu_percent watch for 1 sec = true live value.
    # Beginner note: percpu=True gives a list like [12.0, 5.0, ...] (one per core).
    total_cpu = psutil.cpu_percent(interval=1)
    try:
        per_core = psutil.cpu_percent(interval=0.1, percpu=True)
    except Exception:
        per_core = []

    ram = psutil.virtual_memory()   # physical RAM
    swap = psutil.swap_memory()     # page file / swap

    return {
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "cpu_total_percent": total_cpu,
        "cpu_per_core_percent": per_core,
        "cpu_core_count": psutil.cpu_count(logical=True),
        "ram_total_gb": round(ram.total / (1024 ** 3), 2),
        "ram_used_gb": round(ram.used / (1024 ** 3), 2),
        "ram_available_gb": round(ram.available / (1024 ** 3), 2),
        "ram_percent": ram.percent,
        "swap_total_gb": round(swap.total / (1024 ** 3), 2),
        "swap_used_gb": round(swap.used / (1024 ** 3), 2),
        "swap_percent": swap.percent,
    }


    # ===========================================================================
    # FEATURE 4: BACKGROUND SERVICES & STARTUP PROGRAMS
    # ===========================================================================

def get_windows_services():
    #     List Windows services RIGHT NOW (running / stopped / paused)
    #     with Display Name, Status, and PID (if running).
    #
    #     Uses psutil live API. (Same data as `services.msc`.)
    #
    services = []
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                services.append({
                    "name": info.get("name", ""),
                    "display_name": info.get("display_name", ""),
                    "status": info.get("status", ""),
                    "pid": info.get("pid") or 0,  # 0 means not running
                    "username": info.get("username", ""),
                })
            except Exception:
                continue
    except AttributeError:
        # psutil.win_service_iter only exists on Windows.
        print("[Warning] Windows services are only available on Windows.")
    return services


def get_startup_programs():
    #     Find programs that auto-start at logon/boot by running
    #     LIVE `reg query` on the official Run / RunOnce keys.
    #
    #     This satisfies: 'Scan Registry paths for auto-running applications'.
    #
    #     Returns: list of dicts {registry_path, name, command, raw_output}
    #
    results = []
    for reg_path in REG_STARTUP_PATHS:
        output = run_reg_query(reg_path)
        if not output.strip() or "ERROR" in output:
            # Key does not exist or no permission -- skip quietly.
            continue

        # Typical `reg query` line:
        #     Spotify    REG_SZ    C:\\Users\\...\\Spotify.exe --minimized
        #     Free Download Manager    REG_SZ    "C:\\Program Files\\..."
        # NOTE: the program NAME itself can contain spaces, so we can NOT
        # just split by spaces. We split on the REG_xxx column instead.
        import re
        for line in output.splitlines():
            stripped = line.strip()
            # Skip header lines like "HKEY_..." and empty lines.
            if not stripped or stripped.startswith("HKEY_"):
                continue
            match = re.match(r"^(.*?)\s+(REG_\S+)\s+(.*)$", stripped)
            if not match:
                continue
            entry_name, reg_type, command = match.group(1).strip(), match.group(2).strip(), match.group(3).strip()
            results.append({
                "registry_path": reg_path,
                "name": entry_name,
                "type": reg_type,
                "command": command,
            })

    return results


    # ===========================================================================
    # FEATURE 5: REGISTRY & EVENT VIEWER AUDITING (security logs)
    # ===========================================================================

def get_installed_software():
    #     List installed programs by running LIVE `reg query` on the
    #     official Uninstall keys, reading each program's DisplayName.
    #
    #     Step 1: reg query <UninstallKey>              -> list of sub-keys
    #     Step 2: reg query <UninstallKey>\\<SubKey> /v DisplayName -> program name
    #
    #     Returns: list of {"name": ..., "registry_key": ...}
    #
    software = []

    for base_path in REG_UNINSTALL_PATHS:
        output = run_reg_query(base_path)
        if not output.strip() or "ERROR" in output:
            continue

        # Each line that starts with HKEY_ is one installed program's key.
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("HKEY_"):
                continue

            # Ask Windows for that program's DisplayName.
            detail = run_command(["reg", "query", line, "/v", "DisplayName"])
            for dline in detail.splitlines():
                if "DisplayName" in dline:
                    # Line looks like: "    DisplayName    REG_SZ    Google Chrome"
                    parts = dline.split("REG_SZ")
                    if len(parts) == 2:
                        app_name = parts[1].strip()
                        if app_name:
                            software.append({
                                "name": app_name,
                                "registry_key": line,
                            })
                    break  # only need first DisplayName per key

    # Remove duplicates (same app in both 32-bit and 64-bit keys).
    seen = set()
    unique = []
    for app in software:
        if app["name"].lower() not in seen:
            seen.add(app["name"].lower())
            unique.append(app)

    return sorted(unique, key=lambda x: x["name"].lower())


def check_software_compliance(installed_list=None):
    #     Compare installed software (live from Registry) against BLOCKLISTED_APPS.
    #
    #     Returns: list of banned apps that were FOUND (empty list = compliant/clean).
    #     Each item: {"found_name": ..., "matched_keyword": ...}
    #
    if installed_list is None:
        installed_list = get_installed_software()  # live query

    violations = []
    for app in installed_list:
        app_lower = app["name"].lower()
        for banned in BLOCKLISTED_APPS:
            if banned.lower() in app_lower:
                violations.append({
                    "found_name": app["name"],
                    "matched_keyword": banned,
                })
                break

    return violations


def get_logon_history(count=20):
    # Live successful logons (Event ID 4624) + logoffs (4634) from Security log.
    logons = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["successful_logon"], count))
    logoffs = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["logoff"], count))
    return {"successful_logons_4624": logons, "logoffs_4634": logoffs}


def get_failed_logons(count=20):
    # Live failed login attempts (Event ID 4625) -- intrusion tracking.
    raw = run_wevtutil_query("Security", EVENT_IDS["failed_logon"], count)
    return parse_wevtutil_text(raw)


def get_account_changes(count=20):
    # Live account creation (4720) + privilege escalation (4728).
    created = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["account_created"], count))
    escalated = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["added_to_group"], count))
    return {"accounts_created_4720": created, "privilege_escalations_4728": escalated}


def get_system_crashes(count=20):
    # Live app crashes (1000, Application log) + unexpected shutdowns (6008, System).
    crashes = parse_wevtutil_text(run_wevtutil_query("Application", EVENT_IDS["app_crash"], count))
    shutdowns = parse_wevtutil_text(run_wevtutil_query("System", EVENT_IDS["unexpected_shutdown"], count))
    return {"app_crashes_1000": crashes, "unexpected_shutdowns_6008": shutdowns}


def get_usb_history():
    #     USB history traces: every USB stick EVER plugged in leaves a key here.
    #     Source: reg query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
    #     NOTE: this is HISTORY, not live plug status. A device listed here
    #     may be unplugged right now. Use get_connected_usb_devices() below
    #     to see what is ACTUALLY connected via USB at this moment.
    #
    #     Returns: {"reg_output": raw text, "devices": [device names]}
    #
    raw = run_reg_query(REG_USB_PATH)
    devices = []
    if raw.strip() and "ERROR" not in raw:
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("HKEY_"):
                # Last part of key path is the device ID, e.g. ...\\Disk&Ven_SanDisk...
                devices.append(line.split("\\")[-1] if "\\" in line else line)

    return {"reg_output": raw, "devices": devices}


def get_connected_usb_devices():
    #     ACTUALLY connected USB / removable devices RIGHT NOW (live plug status).
    #     Answers: which device is connected via USB port at this moment?
    #     Sources combined (all live, nothing cached):
    #       1) powershell Get-CimInstance Win32_DiskDrive -> model, interface,
    #          media type, size, serial + mapped drive letters (ONE call, ~1s).
    #       2) powershell Get-CimInstance Win32_LogicalDisk -> volume label,
    #          file system, size, DriveType (2 = removable). Same call as above.
    #       3) psutil partitions + disk_usage -> free space per letter (instant).
    #       4) USBSTOR history cross-check -> mark models seen before via reg query.
    #     A drive counts as USB-connected when ANY of these is true:
    #       media type has External/Removable, interface is USB,
    #       a mapped volume has DriveType 2, psutil says removable,
    #       or the model matches a USBSTOR history entry.
    #     Returns: {"connected": [one dict per live device], "count": N}
    #     Each device: {device_id, model, interface_type, media_type, size_gb,
    #       serial, drive_letters, volumes, connection, status}
    #
    connected = []
    # # Step 1: instant psutil view (removable flag + usage per letter).
    ps_removable = set()
    ps_usage = {}
    try:
        for p in psutil.disk_partitions(all=False):
            try:
                opts = (p.opts or "").lower()
                if "removable" in opts:
                    ps_removable.add(p.device.upper().rstrip("\\"))
            except Exception:
                pass
            try:
                u = psutil.disk_usage(p.mountpoint)
                ps_usage[p.device.upper().rstrip("\\")] = {
                    "mountpoint": p.mountpoint,
                    "fstype": p.fstype,
                    "total_gb": round(u.total / (1024 ** 3), 2),
                    "free_gb": round(u.free / (1024 ** 3), 2),
                }
            except Exception:
                pass
    except Exception:
        pass
    # # Step 2: USBSTOR history models for cross-check (cheap reg query, ~0.04s).
    history_models = []
    try:
        hist = run_reg_query(REG_USB_PATH)
        for line in hist.splitlines():
            line = line.strip()
            if line.startswith("HKEY_"):
                history_models.append(line.upper())
    except Exception:
        pass
    # # Step 3: ONE powershell call for drives + letters + volumes (~1s).
    drives = []
    volumes = {}
    try:
        ps_script = (
            "'SECTION_DRIVES'; "
            "$drives = Get-CimInstance Win32_DiskDrive; "
            "foreach ($d in $drives) { "
            "  $parts = Get-CimAssociatedInstance -InputObject $d -ResultClassName Win32_DiskPartition; "
            "  $letters = @(); "
            "  foreach ($p in $parts) { $lds = Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_LogicalDisk; foreach ($l in $lds) { $letters += $l.DeviceID } }; "
            "  ('DRIVE|' + $d.DeviceID + '|' + $d.Model + '|' + $d.InterfaceType + '|' + $d.MediaType + '|' + $d.Size + '|' + $d.SerialNumber + '|' + ($letters -join ','))"
            "}; "
            "'SECTION_VOLUMES'; "
            "$lds = Get-CimInstance Win32_LogicalDisk; "
            "foreach ($l in $lds) { ('VOL|' + $l.DeviceID + '|' + $l.VolumeName + '|' + $l.FileSystem + '|' + $l.Size + '|' + $l.DriveType) }"
        )
        out = run_command(["powershell", "-NoProfile", "-Command", ps_script])
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("DRIVE|"):
                parts = line.split("|")
                # # DRIVE|DeviceID|Model|Interface|Media|Size|Serial|Letters
                while len(parts) < 8:
                    parts.append("")
                drives.append({
                    "device_id": parts[1],
                    "model": parts[2],
                    "interface_type": parts[3],
                    "media_type": parts[4],
                    "size": parts[5],
                    "serial": parts[6],
                    "letters": [x.strip() for x in parts[7].split(",") if x.strip()],
                })
            elif line.startswith("VOL|"):
                parts = line.split("|")
                # # VOL|Letter|VolumeName|FileSystem|Size|DriveType
                while len(parts) < 6:
                    parts.append("")
                volumes[parts[1].upper()] = {
                    "volume_name": parts[2],
                    "fstype": parts[3],
                    "size": parts[4],
                    "drive_type": parts[5].strip(),
                }
    except Exception:
        pass
    # # Step 4: decide per drive if it is USB-connected, then build the row.
    for d in drives:
        media = (d["media_type"] or "").lower()
        iface = (d["interface_type"] or "").lower()
        model = d["model"] or ""
        letters = d["letters"]
        # # Check each USB signal (any True = connected via USB/removable).
        is_external_media = ("external" in media) or ("removable" in media)
        is_usb_iface = (iface == "usb")
        has_removable_vol = any(volumes.get(x.upper(), {}).get("drive_type") == "2" for x in letters)
        has_ps_removable = any(x.upper() in ps_removable for x in letters)
        # # History match: model words appear in a USBSTOR key (e.g. TS256GSS).
        model_hit = False
        try:
            compact = "".join(model.upper().split())
            for h in history_models:
                if len(compact) >= 6 and compact[:6] in h.replace(" ", ""):
                    model_hit = True
                    break
        except Exception:
            pass
        is_usb = is_external_media or is_usb_iface or has_removable_vol or has_ps_removable or model_hit
        if not is_usb:
            continue
        # # Build per-letter volume details (label, fs, size, free).
        vols = []
        for letter in letters:
            key = letter.upper()
            v = volumes.get(key, {})
            use = ps_usage.get(key, {})
            size_gb = 0.0
            try:
                size_gb = round(int(v.get("size") or 0) / (1024 ** 3), 2)
            except Exception:
                size_gb = use.get("total_gb", 0.0)
            vols.append({
                "letter": letter,
                "volume_name": v.get("volume_name", ""),
                "fstype": v.get("fstype", "") or use.get("fstype", ""),
                "size_gb": size_gb,
                "free_gb": use.get("free_gb", 0.0),
            })
        # # Total size from drive Size bytes, fallback to volumes sum.
        total_gb = 0.0
        try:
            total_gb = round(int(d["size"] or 0) / (1024 ** 3), 2)
        except Exception:
            total_gb = round(sum(x["size_gb"] for x in vols), 2)
        # # Human connection label for the dashboard.
        if has_removable_vol or has_ps_removable:
            connection = "Removable (USB stick / card)"
        elif is_usb_iface:
            connection = "USB"
        else:
            connection = "USB / External"
        connected.append({
            "device_id": d["device_id"],
            "model": model,
            "interface_type": d["interface_type"],
            "media_type": d["media_type"],
            "serial": d["serial"],
            "size_gb": total_gb,
            "drive_letters": letters,
            "volumes": vols,
            "connection": connection,
            "status": "connected",
        })
    return {"connected": connected, "count": len(connected)}


    # ===========================================================================
    # STREAMLIT-READY: one call that grabs EVERYTHING live
    # ===========================================================================

def get_all_live_data(process_limit=100, event_count=10):
    #     Convenience function for the FUTURE Streamlit dashboard.
    #
    #     It calls every live function above and packs results into ONE dict,
    #     so the Streamlit app only needs ONE call:
    #
    #         data = mon.get_all_live_data()
    #         st.metric("CPU %", data["system_summary"]["cpu_total_percent"])
    #         st.dataframe(data["processes"])
    #         ...
    #
    #     process_limit: how many processes to include (keeps dashboard fast)
    #     event_count:   how many Event Viewer entries per category
    #
    return {
        "collected_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "processes": get_process_inventory(limit=process_limit),
        "resources": get_process_resource_usage(limit=process_limit),
        "network": get_network_usage_per_process(),
        "system_summary": get_system_summary(),
        "services": get_windows_services(),
        "startup_programs": get_startup_programs(),
        "installed_software": get_installed_software(),
        "compliance_violations": check_software_compliance(),
        "logons": get_logon_history(count=event_count),
        "failed_logons": get_failed_logons(count=event_count),
        "account_changes": get_account_changes(count=event_count),
        "crashes": get_system_crashes(count=event_count),
        "usb": get_usb_history(),
        "usb_connected": get_connected_usb_devices(),
    }


    # ===========================================================================
    # TEST MODE: run this file directly to see live data in the terminal
    # ===========================================================================

def clear_screen():
    # Clear the terminal so the next live refresh starts on a clean screen.
    # Windows uses cls, Linux/Mac uses clear.
    os.system("cls" if os.name == "nt" else "clear")


def show_snapshot():
    # Print ONE live snapshot of everything to the terminal.
    # This is called again and again by main() in infinite-loop mode.
    print("=" * 70)
    print(" WINDOWS SYSTEM & SECURITY MONITOR -- LIVE (auto-refresh)")
    print(" Collected at:", datetime.datetime.now().isoformat(timespec="seconds"))
    print(" Press Ctrl+C to stop.")
    print("=" * 70)

    print("\n[1] Process inventory (first 5)...")
    for p in get_process_inventory(limit=5):
        print(f"  PID {p['pid']:>6} | {p['name']:<25} | parent: {p['parent_name']} | {p['exe_path']}")

    print("\n[2] Top 5 processes by CPU...")
    for r in get_process_resource_usage(limit=5):
        print(f"  {r['name']:<25} CPU {r['cpu_percent']:>5}% | RAM {r['memory_mb']:>8} MB "
              f"| Disk R {r['disk_read_kbs']} KB/s W {r['disk_write_kbs']} KB/s")

    print("\n[3] System summary...")
    summary = get_system_summary()
    print(f"  CPU total: {summary['cpu_total_percent']}% | cores: {summary['cpu_core_count']}")
    print(f"  RAM: {summary['ram_used_gb']}/{summary['ram_total_gb']} GB ({summary['ram_percent']}%)")
    print(f"  Swap: {summary['swap_used_gb']}/{summary['swap_total_gb']} GB ({summary['swap_percent']}%)")

    print("\n[4] Services (first 3) + Startup programs (first 3)...")
    for s in get_windows_services()[:3]:
        print(f"  Service: {s['display_name']:<40} | {s['status']} | PID {s['pid']}")
    for st in get_startup_programs()[:3]:
        print(f"  Startup: {st['name']:<30} | {st['command'][:70]}")

    print("\n[5] Installed software (first 5) + compliance check...")
    for app in get_installed_software()[:5]:
        print(f"  App: {app['name']}")
    violations = check_software_compliance()
    if violations:
        print(f"  [!] {len(violations)} blocklisted app(s) FOUND:")
        for v in violations:
            print(f"      - {v['found_name']} (matched '{v['matched_keyword']}')")
    else:
        print("  [OK] No blocklisted software found.")

    print("\n[6] Event Viewer (live, 3 events each)...")
    print(f"  Failed logons (4625): {len(get_failed_logons(count=3))} fetched")
    print(f"  Unexpected shutdowns (6008): {len(get_system_crashes(count=3)['unexpected_shutdowns_6008'])} fetched")

    print("\n[7] USB history + currently connected...")
    usb = get_usb_history()
    print(f"  USB history traces (ever plugged in): {len(usb['devices'])}")
    for d in usb["devices"][:3]:
        print(f"    - {d}")
    # # Live plug status: which removable/USB device is connected RIGHT NOW.
    live = get_connected_usb_devices()
    print(f"  Currently connected via USB: {live['count']}")
    for dev in live["connected"]:
        letters = ",".join(dev["drive_letters"]) if dev["drive_letters"] else "no letter"
        print(f"    - {dev['model']} [{letters}] {dev['size_gb']} GB ({dev['connection']})")
        for v in dev["volumes"]:
            print(f"        {v['letter']} {v['volume_name']} {v['fstype']} {v['size_gb']} GB free {v['free_gb']} GB")

    print("\nDone. All data above was read LIVE just now.")
    print("Next step: build Streamlit dashboard on top of get_all_live_data().")


def main(refresh_seconds=REFRESH_SECONDS, once=False):
    # Run forever: clear screen, show live data, wait, repeat.
    # refresh_seconds = pause between refreshes.
    # once = if True, show only one snapshot and stop (useful for testing).
    # Stop anytime with Ctrl+C.
    try:
        while True:
            clear_screen()
            show_snapshot()
            if once:
                break
            print(f"\nRefreshing in {refresh_seconds} seconds... (Ctrl+C to stop)")
            time.sleep(refresh_seconds)
    except KeyboardInterrupt:
        # User pressed Ctrl+C, exit quietly without an error message.
        print("\nStopped by user. Bye!")
        sys.exit(0)


if __name__ == "__main__":
    # Read simple options from the command line (all optional, beginner-friendly).
    # python system_security_monitor.py                  -> loop every 5 sec
    # python system_security_monitor.py --once            -> run one time and stop
    # python system_security_monitor.py --interval 10     -> loop every 10 sec
    interval = REFRESH_SECONDS
    run_once = False
    args = sys.argv[1:]
    if "--once" in args:
        run_once = True
    if "--interval" in args:
        try:
            pos = args.index("--interval")
            interval = int(args[pos + 1])
        except Exception:
            # If the user types a bad number, keep the default and keep running.
            print(f"[Warning] Bad --interval value, using default {REFRESH_SECONDS} sec.")
            interval = REFRESH_SECONDS
    main(refresh_seconds=interval, once=run_once)


    # ===========================================================================
    # FUTURE STREAMLIT DASHBOARD (NOT active yet -- copy into app.py later)
    # ===========================================================================
    # import streamlit as st
    # import system_security_monitor as mon
    #
    # st.set_page_config(page_title="Windows Security Monitor", layout="wide")
    # st.title("🖥️ Windows System & Security Monitor (LIVE)")
    #
    # if st.button("🔄 Refresh (re-read live data)"):
    #     st.rerun()
    #
    # data = mon.get_all_live_data(process_limit=100, event_count=10)
    #
    # # --- Top metrics ---
    # s = data["system_summary"]
    # c1, c2, c3 = st.columns(3)
    # c1.metric("CPU Total %", s["cpu_total_percent"])
    # c2.metric("RAM Used %", s["ram_percent"])
    # c3.metric("Swap Used %", s["swap_percent"])
    #
    # # --- Tabs for each feature section ---
    # tab1, tab2, tab3, tab4, tab5 = st.tabs([
    #     "Processes", "Resources", "Services & Startup", "Software Audit", "Security Logs"
    # ])
    # with tab1:
    #     st.dataframe(data["processes"], use_container_width=True)
    # with tab2:
    #     st.dataframe(data["resources"], use_container_width=True)
    # with tab3:
    #     st.dataframe(data["services"], use_container_width=True)
    #     st.dataframe(data["startup_programs"], use_container_width=True)
    # with tab4:
    #     st.dataframe(data["installed_software"], use_container_width=True)
    #     st.write("Violations:", data["compliance_violations"])
    # with tab5:
    #     st.write("Failed logons (4625):", data["failed_logons"])
    #     st.write("Account changes:", data["account_changes"])
    #     st.write("Crashes:", data["crashes"])
    #     st.write("USB devices:", data["usb"]["devices"])
    # ===========================================================================
