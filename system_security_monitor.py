# Windows System & Security Monitor: live queries via psutil/reg/wevtutil.
import subprocess
import psutil
import datetime
import time
import os
import sys


BLOCKLISTED_APPS = [
    "utorrent",
    "bittorrent",
    "anydesk",
    "teamviewer",
    "crack",
    "keygen",
]


EVENT_IDS = {
    "successful_logon": 4624,
    "logoff": 4634,
    "failed_logon": 4625,
    "account_created": 4720,
    "added_to_group": 4728,
    "app_crash": 1000,
    "unexpected_shutdown": 6008,
}


REG_STARTUP_PATHS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]


REG_UNINSTALL_PATHS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]


REG_USB_PATH = r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"


REFRESH_SECONDS = 5


def run_command(command_list):
    # Run Windows command and return stdout or empty string.
    try:
        result = subprocess.run(
            command_list,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout
    except Exception as e:
        print(f"[Warning] Command failed {' '.join(command_list)}: {e}")
        return ""


def run_reg_query(registry_path):
    # Query registry path via reg query.
    return run_command(["reg", "query", registry_path])


def run_wevtutil_query(log_name, event_id, count=20):
    # Query Event Viewer via wevtutil for one event ID.
    xpath = f"*[System[(EventID={event_id})]]"
    command = [
        "wevtutil", "qe", log_name,
        f"/q:{xpath}",
        "/f:text",
        f"/c:{count}",
        "/rd:true",
    ]
    return run_command(command)


def parse_wevtutil_text(raw_text):
    # Parse wevtutil text into list of event dicts.
    events = []
    if not raw_text.strip():
        return events


    blocks = raw_text.split("Event[")
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        full_block = "Event[" + block


        info = {"raw": full_block}
        for line in full_block.splitlines():
            line = line.strip()

            if line.startswith("Date:"):
                info["Date"] = line.replace("Date:", "").strip()
            elif line.startswith("Event ID:"):
                info["Event ID"] = line.replace("Event ID:", "").strip()
            elif line.startswith("Description:"):
                info["Description"] = line.replace("Description:", "").strip()

        events.append(info)

    return events


def get_process_inventory(limit=None):
    # List live processes with PID, path and parent.
    inventory = []


    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            data = proc.info


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

                "cmdline": " ".join(data["cmdline"]) if data["cmdline"] else "",
                "parent_pid": data["ppid"],
                "parent_name": parent_name,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):

            continue

    if limit is not None:
        inventory = inventory[:limit]

    return inventory


def get_process_resource_usage(limit=None):
    # Live CPU/RAM/disk rate per process (1s sample).
    procs = list(psutil.process_iter(["pid", "name", "memory_info"]))
    for proc in procs:
        try:
            proc.cpu_percent(interval=None)
            try:
                proc.io_counters()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


    first_snapshot = {}
    for proc in procs:
        try:
            io = proc.io_counters()
            first_snapshot[proc.info["pid"]] = (proc.info["name"], io.read_bytes, io.write_bytes)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


    import time
    time.sleep(1.0)


    results = []
    for proc in procs:
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or "Unknown"


            cpu = proc.cpu_percent(interval=0.0)


            ram_mb = round(proc.info["memory_info"].rss / (1024 * 1024), 2)


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


    results.sort(key=lambda x: x["cpu_percent"], reverse=True)

    if limit is not None:
        results = results[:limit]

    return results


def get_network_usage_per_process():
    # Live open sockets per process plus NIC speed.
    connections = psutil.net_connections(kind="inet")
    per_process = {}

    for conn in connections:
        pid = conn.pid
        if pid is None:
            continue
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


    io1 = psutil.net_io_counters()
    import time
    time.sleep(1)
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
            "sockets": sock_list[:5],
        })


    rows.sort(key=lambda x: x["open_connections"], reverse=True)

    return {
        "system_sent_kbs": sent_kbs,
        "system_recv_kbs": recv_kbs,
        "per_process": rows,
    }


def get_system_summary():
    # Overall CPU/RAM/swap health right now.
    total_cpu = psutil.cpu_percent(interval=1)
    try:
        per_core = psutil.cpu_percent(interval=0.1, percpu=True)
    except Exception:
        per_core = []

    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()

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


def get_windows_services():
    # List Windows services with status and PID.
    services = []
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                services.append({
                    "name": info.get("name", ""),
                    "display_name": info.get("display_name", ""),
                    "status": info.get("status", ""),
                    "pid": info.get("pid") or 0,
                    "username": info.get("username", ""),
                })
            except Exception:
                continue
    except AttributeError:

        print("[Warning] Windows services are only available on Windows.")
    return services


def get_startup_programs():
    # Auto-start apps from Registry Run keys.
    results = []
    for reg_path in REG_STARTUP_PATHS:
        output = run_reg_query(reg_path)
        if not output.strip() or "ERROR" in output:

            continue


        import re
        for line in output.splitlines():
            stripped = line.strip()

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


def get_installed_software():
    # Installed apps from Uninstall registry keys.
    software = []

    for base_path in REG_UNINSTALL_PATHS:
        output = run_reg_query(base_path)
        if not output.strip() or "ERROR" in output:
            continue


        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("HKEY_"):
                continue


            detail = run_command(["reg", "query", line, "/v", "DisplayName"])
            for dline in detail.splitlines():
                if "DisplayName" in dline:

                    parts = dline.split("REG_SZ")
                    if len(parts) == 2:
                        app_name = parts[1].strip()
                        if app_name:
                            software.append({
                                "name": app_name,
                                "registry_key": line,
                            })
                    break


    seen = set()
    unique = []
    for app in software:
        if app["name"].lower() not in seen:
            seen.add(app["name"].lower())
            unique.append(app)

    return sorted(unique, key=lambda x: x["name"].lower())


def check_software_compliance(installed_list=None):
    # Flag installed apps matching blocklist.
    if installed_list is None:
        installed_list = get_installed_software()

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
    # Successful logons (4624) and logoffs (4634).
    logons = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["successful_logon"], count))
    logoffs = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["logoff"], count))
    return {"successful_logons_4624": logons, "logoffs_4634": logoffs}


def get_failed_logons(count=20):
    # Failed logons (4625) for intrusion tracking.
    raw = run_wevtutil_query("Security", EVENT_IDS["failed_logon"], count)
    return parse_wevtutil_text(raw)


def get_account_changes(count=20):
    # Account creations (4720) and privilege adds (4728).
    created = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["account_created"], count))
    escalated = parse_wevtutil_text(run_wevtutil_query("Security", EVENT_IDS["added_to_group"], count))
    return {"accounts_created_4720": created, "privilege_escalations_4728": escalated}


def get_system_crashes(count=20):
    # App crashes (1000) and shutdowns (6008).
    crashes = parse_wevtutil_text(run_wevtutil_query("Application", EVENT_IDS["app_crash"], count))
    shutdowns = parse_wevtutil_text(run_wevtutil_query("System", EVENT_IDS["unexpected_shutdown"], count))
    return {"app_crashes_1000": crashes, "unexpected_shutdowns_6008": shutdowns}


def get_usb_history():
    # USB devices ever plugged in (USBSTOR traces).
    raw = run_reg_query(REG_USB_PATH)
    devices = []
    if raw.strip() and "ERROR" not in raw:
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("HKEY_"):

                devices.append(line.split("\\")[-1] if "\\" in line else line)

    return {"reg_output": raw, "devices": devices}


def get_connected_usb_devices():
    # USB devices connected right now.
    connected = []

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

    history_models = []
    try:
        hist = run_reg_query(REG_USB_PATH)
        for line in hist.splitlines():
            line = line.strip()
            if line.startswith("HKEY_"):
                history_models.append(line.upper())
    except Exception:
        pass

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

    for d in drives:
        media = (d["media_type"] or "").lower()
        iface = (d["interface_type"] or "").lower()
        model = d["model"] or ""
        letters = d["letters"]

        is_external_media = ("external" in media) or ("removable" in media)
        is_usb_iface = (iface == "usb")
        has_removable_vol = any(volumes.get(x.upper(), {}).get("drive_type") == "2" for x in letters)
        has_ps_removable = any(x.upper() in ps_removable for x in letters)

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

        total_gb = 0.0
        try:
            total_gb = round(int(d["size"] or 0) / (1024 ** 3), 2)
        except Exception:
            total_gb = round(sum(x["size_gb"] for x in vols), 2)

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


def get_all_live_data(process_limit=100, event_count=10):
    # Collect all live data into one dict.
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


def clear_screen():
    # Clear terminal for next refresh.
    os.system("cls" if os.name == "nt" else "clear")


def show_snapshot():
    # Print one live terminal snapshot.
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
    # Loop showing snapshots until Ctrl+C or --once.
    try:
        while True:
            clear_screen()
            show_snapshot()
            if once:
                break
            print(f"\nRefreshing in {refresh_seconds} seconds... (Ctrl+C to stop)")
            time.sleep(refresh_seconds)
    except KeyboardInterrupt:

        print("\nStopped by user. Bye!")
        sys.exit(0)


if __name__ == "__main__":


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

            print(f"[Warning] Bad --interval value, using default {REFRESH_SECONDS} sec.")
            interval = REFRESH_SECONDS
    main(refresh_seconds=interval, once=run_once)
