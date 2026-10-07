# Streamlit single-page dashboard for Windows System & Security Monitor.
# Run with: streamlit run dashboard_app.py
# This file only draws the UI. All live data comes from system_security_monitor.py.
# Beginner note: each chart is a small function so you can change one without breaking others.
# Eye-comfort theme: soft dark slate background, muted blue/green bars, red ONLY for top/alert.
# Auto-refresh: sidebar toggle + seconds box, the page re-reads live data on every refresh.
# Time filter: sidebar Last hour / 24 hours / 7 days / 30 days, all charts respect it.

import os
import time
import json
import datetime
import pandas as pd
import altair as alt
import streamlit as st

import system_security_monitor as mon

# ---------------------------------------------------------------------------
# # Config: files, colors, time ranges (change here, UI updates everywhere).
# ---------------------------------------------------------------------------
# # CSV file next to this script that stores one row per snapshot over time.
# # This is what makes Hours/Days/Weeks/Months filters possible.
HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_history.csv")
# # JSON file remade every refresh (default 2 seconds). Dashboard updates FROM this file.
# # Flow: wait 2s -> fetch live -> write JSON -> read JSON -> redraw dashboard.
SNAPSHOT_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_snapshot.json")
# # Fixed refresh interval in seconds as requested (2 seconds).
REFRESH_SECONDS = 2
# # USB-only JSON remade every 2 seconds by a background watcher thread.
# # USB reg query takes ~0.04s, so it can truly hit 2s even though a full
# # snapshot (CPU sampling + software scan) takes ~20s. Dashboard reads USB
# # from this file on every render, so the USB card updates every 2 seconds.
USB_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usb_live.json")
USB_INTERVAL = 2

# # Soft eye-comfort palette (muted, not neon/retro).
COLOR_BG = "#111827"
COLOR_CARD = "#1F2937"
COLOR_TEXT = "#E5E7EB"
COLOR_MUTED = "#9CA3AF"
COLOR_BAR = "#7BA7C7"
COLOR_BAR2 = "#8FB996"
COLOR_LINE = "#7BA7C7"
COLOR_LINE2 = "#C9B48A"
COLOR_RED = "#E07A7A"

# # Sidebar time options -> hours as number. Months = 30 days.
TIME_RANGES = {
    "Last hour": 1,
    "Last 24 hours": 24,
    "Last 7 days": 24 * 7,
    "Last 30 days": 24 * 30,
}

# ---------------------------------------------------------------------------
# # History helpers: save each live snapshot so charts have a time axis.
# ---------------------------------------------------------------------------
def save_snapshot(cpu_total, ram_pct, swap_pct, failed_count):
    # # Append one row: timestamp + 4 numbers. Creates the CSV on first run.
    # # Throttling is done by the caller (only save every N seconds).
    now = datetime.datetime.now()
    row = pd.DataFrame([{
        "timestamp": now,
        "cpu_total": cpu_total,
        "ram_pct": ram_pct,
        "swap_pct": swap_pct,
        "failed_total": failed_count,
    }])
    if os.path.exists(HISTORY_FILE):
        old = pd.read_csv(HISTORY_FILE, parse_dates=["timestamp"])
        new = pd.concat([old, row], ignore_index=True)
    else:
        new = row
    # # Keep file small: last 30 days only (about 40k rows at 60s interval max).
    # # Beginners: this prevents the CSV growing forever.
    try:
        cutoff = pd.Timestamp.now() - pd.Timedelta(days=32)
        new["timestamp"] = pd.to_datetime(new["timestamp"])
        new = new[new["timestamp"] >= cutoff]
    except Exception:
        pass
    new.to_csv(HISTORY_FILE, index=False)


def load_history():
    # # Read history CSV, return empty DataFrame with right columns if missing.
    try:
        if os.path.exists(HISTORY_FILE):
            df = pd.read_csv(HISTORY_FILE, parse_dates=["timestamp"])
            return df
    except Exception:
        pass
    return pd.DataFrame(columns=["timestamp", "cpu_total", "ram_pct", "swap_pct", "failed_total"])


def filter_by_range(df, hours):
    # # Keep only rows newer than (now - hours). Used by every time-based chart.
    if df.empty:
        return df
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    cutoff = pd.Timestamp.now() - pd.Timedelta(hours=hours)
    return df[df["timestamp"] >= cutoff].sort_values("timestamp")


# ---------------------------------------------------------------------------
# # JSON snapshot helpers: JSON is remade every 2s, dashboard reads FROM it.
# ---------------------------------------------------------------------------
def save_snapshot_json(snapshot):
    # # Write the fresh snapshot dict to live_snapshot.json on disk.
    # # datetime objects are converted to strings so json can save them.
    data = dict(snapshot)
    fetched = data.get("fetched_at", None)
    if isinstance(fetched, datetime.datetime):
        data["fetched_at"] = fetched.isoformat(timespec="seconds")
        data["updated_at"] = fetched.strftime("%H:%M:%S")
    else:
        now_str = datetime.datetime.now()
        data["fetched_at"] = str(fetched) if fetched else now_str.isoformat(timespec="seconds")
        data["updated_at"] = now_str.strftime("%H:%M:%S")
    with open(SNAPSHOT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data


def load_snapshot_json():
    # # Read live_snapshot.json back from disk. Returns None if missing/broken.
    # # Dashboard always renders from this file, never from stale memory.
    try:
        if os.path.exists(SNAPSHOT_JSON):
            with open(SNAPSHOT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
            # # Convert fetched_at string back to datetime for age math.
            try:
                data["fetched_at"] = datetime.datetime.fromisoformat(data["fetched_at"])
            except Exception:
                data["fetched_at"] = datetime.datetime.now()
            return data
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# # USB 2-second watcher: background thread remakes usb_live.json every 2s.
# ---------------------------------------------------------------------------
# # Module-level flag so only ONE watcher thread runs per server process.
# # Without this, every Streamlit rerun would start another thread.
_USB_WATCHER_STARTED = False

def fetch_usb_fast():
    # # USB read every 2s: history traces (reg query, ~0.04s) PLUS live plug
    # # status (powershell + psutil, ~1.1s). Combined ~1.2s, fits the 2s rhythm
    # # with adaptive sleep in _usb_watch_loop() below.
    # # Returns history devices + currently connected removable devices.
    now = datetime.datetime.now()
    try:
        usb = mon.get_usb_history()
    except Exception:
        usb = {"reg_output": "", "devices": []}
    try:
        live = mon.get_connected_usb_devices()
    except Exception:
        live = {"connected": [], "count": 0}
    return {
        "devices": usb.get("devices", []),
        "count": len(usb.get("devices", [])),
        "connected": live.get("connected", []),
        "connected_count": live.get("count", 0),
        "fetched_at": now.isoformat(timespec="seconds"),
        "usb_updated_at": now.strftime("%H:%M:%S"),
    }


def save_usb_json(usb_data):
    # # Write the USB dict to usb_live.json (overwrites each time).
    with open(USB_JSON, "w", encoding="utf-8") as f:
        json.dump(usb_data, f, indent=2)
    return usb_data


def load_usb_json():
    # # Read usb_live.json. Returns None if the watcher has not written yet.
    try:
        if os.path.exists(USB_JSON):
            with open(USB_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return None


def _usb_watch_loop():
    # # Infinite loop for the background thread: fetch USB, write JSON, sleep.
    # # Adaptive sleep keeps the period at ~2s: sleep only (2 - fetch_time).
    # # Runs forever as a daemon, so it never blocks the dashboard from stopping.
    while True:
        start = time.time()
        try:
            save_usb_json(fetch_usb_fast())
        except Exception:
            pass
        elapsed = time.time() - start
        time.sleep(max(0.1, USB_INTERVAL - elapsed))


def ensure_usb_watcher():
    # # Start the background USB thread once. Call at the top of main().
    # # After this, usb_live.json is guaranteed fresh within the last ~2 seconds.
    global _USB_WATCHER_STARTED
    if _USB_WATCHER_STARTED:
        return
    _USB_WATCHER_STARTED = True
    import threading
    t = threading.Thread(target=_usb_watch_loop, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# # Chart builders (modular: each returns an Altair chart, no Streamlit inside).
# # Top bar is red, rest are muted. This satisfies "toppest will be red".
# ---------------------------------------------------------------------------
def make_top_bar(df, label_col, value_col, title):
    # # df needs columns [label_col, value_col], already sorted high -> low.
    # # We add a rank column: rank 1 = red, others = muted blue.
    if df.empty:
        return alt.Chart(pd.DataFrame({label_col: [], value_col: []})).mark_text().encode()
    d = df.copy().head(10)
    d["is_top"] = (range(1, len(d) + 1) == 1) if len(d) else False
    # # Above line is tricky for beginners, simpler version below:
    d["is_top"] = [True] + [False] * (len(d) - 1)
    chart = alt.Chart(d).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
        x=alt.X(value_col, title=value_col),
        y=alt.Y(label_col, sort="-x", title=""),
        color=alt.condition(
            alt.datum.is_top,
            alt.value(COLOR_RED),
            alt.value(COLOR_BAR),
        ),
        tooltip=[label_col, value_col],
    ).properties(title=title, height=260)
    return chart


def make_failed_line(events, hours):
    # # events = list of dicts from mon.get_failed_logons(), each has "Date".
    # # We parse dates, keep only the selected range, bucket by hour (or day for long ranges).
    rows = []
    for e in events:
        raw = e.get("Date", "")
        try:
            ts = pd.to_datetime(raw, errors="coerce")
            if pd.isna(ts):
                continue
            # # Make timezone-naive so comparison with now() works.
            if getattr(ts, "tzinfo", None) is not None:
                ts = ts.tz_localize(None) if hasattr(ts, "tz_localize") else ts.replace(tzinfo=None)
            rows.append(ts)
        except Exception:
            continue
    if not rows:
        return None, pd.DataFrame(columns=["bucket", "attempts"])
    df = pd.DataFrame({"timestamp": rows})
    cutoff = pd.Timestamp.now() - pd.Timedelta(hours=hours)
    df = df[df["timestamp"] >= cutoff]
    if df.empty:
        return None, pd.DataFrame(columns=["bucket", "attempts"])
    # # Bucket size: hour for short ranges, day for 7/30 days (keeps line readable).
    rule = "h" if hours <= 24 else "D"
    df["bucket"] = df["timestamp"].dt.floor(rule)
    line_df = df.groupby("bucket").size().reset_index(name="attempts").sort_values("bucket")
    chart = alt.Chart(line_df).mark_line(point=True, color=COLOR_RED).encode(
        x=alt.X("bucket:T", title="time"),
        y=alt.Y("attempts:Q", title="failed attempts"),
        tooltip=["bucket:T", "attempts:Q"],
    ).properties(title="Failed login attempts over time (Event 4625)", height=260)
    return chart, line_df


def make_perf_history_line(hist_df):
    # # Long/melted line chart: CPU% and RAM% over time from history CSV.
    if hist_df.empty or len(hist_df) < 1:
        return None
    long_df = hist_df.melt(id_vars=["timestamp"], value_vars=["cpu_total", "ram_pct"], var_name="metric", value_name="pct")
    chart = alt.Chart(long_df).mark_line(point=False).encode(
        x=alt.X("timestamp:T", title="time"),
        y=alt.Y("pct:Q", title="%"),
        color=alt.Color("metric:N", scale=alt.Scale(range=[COLOR_LINE, COLOR_BAR2])),
        tooltip=["timestamp:T", "metric:N", "pct:Q"],
    ).properties(title="System CPU / RAM history", height=260)
    return chart


# ---------------------------------------------------------------------------
# # Page style: soft dark cards like the reference image, but muted for long viewing.
# ---------------------------------------------------------------------------
def apply_style():
    # # Inject CSS: dark background, rounded cards, soft text. No neon colors.
    # # update-badge is fixed in the top-right corner showing last updated time.
    st.markdown(
        "<style>"
        ".stApp { background-color: #111827; color: #E5E7EB; }"
        ".card { background-color: #1F2937; border-radius: 12px; padding: 16px; margin-bottom: 12px; }"
        ".metric-big { font-size: 34px; font-weight: 700; }"
        ".red-text { color: #E07A7A; font-weight: 600; }"
        ".muted { color: #9CA3AF; font-size: 13px; }"
        ".update-badge { position: fixed; top: 12px; right: 16px; z-index: 9999; background-color: #1F2937; border: 1px solid #374151; border-radius: 8px; padding: 6px 12px; font-size: 13px; color: #E5E7EB; }"
        ".update-badge b { color: #8FB996; }"
        "</style>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# # Corner clock: fixed top-right badge with the JSON updated time.
# ---------------------------------------------------------------------------
def show_update_time(snapshot, usb_live=None):
    # # Reads updated_at (written when JSON was made) and pins it top-right.
    # # Shows both full-snapshot time and USB 2-second time in the corner.
    # # This proves the dashboard redrew AFTER the JSON files were remade.
    label = snapshot.get("updated_at", "")
    if not label:
        try:
            label = snapshot.get("fetched_at", datetime.datetime.now()).strftime("%H:%M:%S")
        except Exception:
            label = datetime.datetime.now().strftime("%H:%M:%S")
    usb_label = ""
    if isinstance(usb_live, dict):
        usb_label = usb_live.get("usb_updated_at", "")
    if usb_label:
        st.markdown("<div class='update-badge'>Updated <b>" + str(label) + "</b> | USB <b>" + str(usb_label) + "</b></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='update-badge'>Updated <b>" + str(label) + "</b></div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# # Live fetch: one place that reads everything fresh from Windows.
# # Called in background while old data stays on screen (see main() below).
# ---------------------------------------------------------------------------
def fetch_live_snapshot(top_n, event_count):
    # # Each call below queries Windows RIGHT NOW (live, nothing cached).
    # # This takes a few seconds (CPU/RAM/network each sample for 1 sec).
    # # USB history is cheap here; live connected devices come from the 2s
    # # watcher file, with a direct call as fallback if the file is missing.
    snapshot = {}
    snapshot["summary"] = mon.get_system_summary()
    snapshot["resources"] = mon.get_process_resource_usage(limit=top_n)
    snapshot["failed_events"] = mon.get_failed_logons(count=event_count)
    snapshot["violations"] = mon.check_software_compliance()
    snapshot["usb"] = mon.get_usb_history()
    try:
        snapshot["usb_connected"] = mon.get_connected_usb_devices()
    except Exception:
        snapshot["usb_connected"] = {"connected": [], "count": 0}
    snapshot["crashes"] = mon.get_system_crashes(count=5)
    snapshot["startup"] = mon.get_startup_programs()
    snapshot["services"] = mon.get_windows_services()
    snapshot["fetched_at"] = datetime.datetime.now()
    return snapshot


# ---------------------------------------------------------------------------
# # Render: draw the whole single-page dashboard from an ALREADY-ready snapshot.
# # No Windows calls here, so it is instant and never blanks the screen.
# ---------------------------------------------------------------------------
def render_dashboard(snapshot, hours, range_label):
    # # Unpack the snapshot dict prepared by fetch_live_snapshot().
    # # USB is re-read from usb_live.json here, so it is at most ~2s old
    # # even when the rest of the snapshot is older (heavy scan takes ~20s).
    # # Corner clock is drawn first so update time is always visible top-right.
    usb_live = load_usb_json()
    show_update_time(snapshot, usb_live)
    summary = snapshot["summary"]
    resources = snapshot["resources"]
    failed_events = snapshot["failed_events"]
    violations = snapshot["violations"]
    # # Prefer the 2-second USB file over the snapshot copy when available.
    # # usb_live.json now carries BOTH history traces and live connected devices.
    if isinstance(usb_live, dict) and "devices" in usb_live:
        usb = {"devices": usb_live.get("devices", []), "reg_output": ""}
        usb_time = usb_live.get("usb_updated_at", "")
        usb_connected = usb_live.get("connected", [])
    else:
        usb = snapshot["usb"]
        usb_time = ""
        usb_connected = snapshot.get("usb_connected", {}).get("connected", []) if isinstance(snapshot.get("usb_connected"), dict) else []
    crashes = snapshot["crashes"]
    startup = snapshot["startup"]
    services = snapshot["services"]
    fetched_at = snapshot.get("fetched_at", None)
    # # History file is re-read here so the time filter always uses latest CSV.
    hist_all = load_history()
    hist = filter_by_range(hist_all, hours)
    # # Small header line shows when this snapshot was taken.
    if fetched_at is not None:
        try:
            age = int((datetime.datetime.now() - fetched_at).total_seconds())
            st.caption("Showing data from " + fetched_at.strftime("%H:%M:%S") + " (" + str(age) + "s ago) | range " + range_label)
        except Exception:
            pass
    # # Top metric cards in one row (like Total Orders card in reference).
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("CPU total %", summary["cpu_total_percent"])
    m2.metric("RAM used %", summary["ram_percent"])
    m3.metric("Swap used %", summary["swap_percent"])
    m4.metric("Failed logons (this query)", len(failed_events))
    m5.metric("Blocked apps found", len(violations))
    # # Row 1: CPU bar + RAM bar side by side. Toppest bar is red.
    st.subheader("Performance by process")
    c1, c2 = st.columns(2)
    res_df = pd.DataFrame(resources)
    with c1:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        if not res_df.empty:
            cpu_df = res_df[["name", "cpu_percent"]].copy()
            cpu_df["name"] = cpu_df["name"] + " (" + res_df["pid"].astype(str) + ")"
            st.altair_chart(make_top_bar(cpu_df, "name", "cpu_percent", "Top CPU % by process"), use_container_width=True)
        else:
            st.info("No process data.")
        st.markdown("</div>", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        if not res_df.empty:
            ram_df = res_df[["name", "memory_mb"]].copy()
            ram_df["name"] = ram_df["name"] + " (" + res_df["pid"].astype(str) + ")"
            st.altair_chart(make_top_bar(ram_df, "name", "memory_mb", "Top RAM MB by process"), use_container_width=True)
        else:
            st.info("No process data.")
        st.markdown("</div>", unsafe_allow_html=True)
    # # Row 2: failed-logon line + system history line side by side, both follow time filter.
    st.subheader("Trends over time (" + range_label + ")")
    t1, t2 = st.columns(2)
    with t1:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        chart, line_df = make_failed_line(failed_events, hours)
        if chart is not None:
            st.altair_chart(chart, use_container_width=True)
            st.dataframe(line_df, use_container_width=True, height=160)
        else:
            # # Empty usually means: need Admin for Security log, or no failures in range.
            st.warning("No failed-logon events in this range. Run as Admin to read the Security log (Event 4625).")
        st.markdown("</div>", unsafe_allow_html=True)
    with t2:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        perf_chart = make_perf_history_line(hist)
        if perf_chart is not None and len(hist) >= 2:
            st.altair_chart(perf_chart, use_container_width=True)
            st.caption(str(len(hist)) + " snapshots in range. History builds each refresh in dashboard_history.csv.")
        else:
            # # First runs have only 1 point, so show live numbers instead of an empty chart.
            st.info("History is building (need 2+ refreshes). Live now: CPU " + str(summary["cpu_total_percent"]) + "% / RAM " + str(summary["ram_percent"]) + "%.")
            if not hist.empty:
                st.dataframe(hist.tail(5), use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    # # Row 3: blocked apps (red text) + USB + crashes, same page, no navigation.
    st.subheader("Security findings")
    s1, s2, s3 = st.columns(3)
    with s1:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.write("Blocked / excluded apps")
        if violations:
            # # Each violating app name is shown in red text as requested.
            for v in violations:
                st.markdown("<span class='red-text'>" + v["found_name"] + "</span> <span class='muted'>(matched '" + v["matched_keyword"] + "')</span>", unsafe_allow_html=True)
        else:
            st.success("Clean: no blocked software found.")
        st.markdown("</div>", unsafe_allow_html=True)
    with s2:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        # # USB card has two parts: live connected devices (every 2s) + history.
        # # Live part answers: which removable device is connected RIGHT NOW.
        if usb_time:
            st.write("USB connected now (" + str(len(usb_connected)) + ") - updated " + str(usb_time) + " (every 2s)")
        else:
            st.write("USB connected now (" + str(len(usb_connected)) + ")")
        if usb_connected:
            # # One row per live device: model + letters + size + free space.
            live_rows = []
            for dev in usb_connected:
                letters = ",".join(dev.get("drive_letters", [])) or "-"
                vols = dev.get("volumes", [])
                free_txt = ""
                try:
                    free_txt = ", ".join([v.get("letter", "") + " free " + str(v.get("free_gb", 0)) + " GB" for v in vols])
                except Exception:
                    free_txt = ""
                live_rows.append({"device": dev.get("model", ""), "drives": letters, "size GB": dev.get("size_gb", 0), "free": free_txt, "link": dev.get("connection", "")})
            st.dataframe(pd.DataFrame(live_rows), use_container_width=True, height=160)
        else:
            st.info("Nothing connected via USB right now.")
        st.write("History traces (" + str(len(usb.get("devices", []))) + ", ever plugged in)")
        devs = usb.get("devices", [])[:5]
        if devs:
            st.dataframe(pd.DataFrame({"device": devs}), use_container_width=True, height=130)
        else:
            st.info("No USBSTOR traces.")
        st.markdown("</div>", unsafe_allow_html=True)
    with s3:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.write("Crashes / shutdowns")
        crash_rows = []
        for e in crashes.get("app_crashes_1000", [])[:3]:
            crash_rows.append({"type": "app crash 1000", "date": e.get("Date", "")})
        for e in crashes.get("unexpected_shutdowns_6008", [])[:3]:
            crash_rows.append({"type": "shutdown 6008", "date": e.get("Date", "")})
        if crash_rows:
            st.dataframe(pd.DataFrame(crash_rows), use_container_width=True, height=200)
        else:
            st.info("No crash events fetched.")
        st.markdown("</div>", unsafe_allow_html=True)
    # # Row 4: details tables (startup, services, live processes) still on the same page.
    st.subheader("Details (live tables)")
    d1, d2 = st.columns(2)
    with d1:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.write("Startup programs (Registry Run keys)")
        if startup:
            st.dataframe(pd.DataFrame(startup)[["name", "command"]].head(15), use_container_width=True, height=240)
        else:
            st.info("No startup entries.")
        st.markdown("</div>", unsafe_allow_html=True)
    with d2:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.write("Services (first 15)")
        if services:
            st.dataframe(pd.DataFrame(services)[["display_name", "status", "pid"]].head(15), use_container_width=True, height=240)
        else:
            st.info("No service data (Windows only).")
        st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.write("Live processes (top by CPU)")
    if not res_df.empty:
        st.dataframe(res_df[["pid", "name", "cpu_percent", "memory_mb", "disk_read_kbs", "disk_write_kbs"]], use_container_width=True, height=260)
    st.caption("Collected at " + summary.get("timestamp", "") + " | range " + range_label + " | history file dashboard_history.csv")
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# # Main: stale-while-revalidate loop. Old data stays until new data is ready.
# ---------------------------------------------------------------------------
def main():
    # # Page title and layout must be the first Streamlit call.
    # # Cycle: show old JSON -> wait 2s -> fetch -> remake JSON -> redraw from JSON.
    st.set_page_config(page_title="Windows Security Monitor", layout="wide")
    apply_style()
    # # Start the USB background thread first: it remakes usb_live.json every 2s
    # # on its own, so the USB card stays on a strict 2s rhythm even while the
    # # full snapshot below takes ~20s (CPU sampling + software scan are slow).
    ensure_usb_watcher()
    st.title("Windows System & Security Monitor")
    # # Sidebar controls: time range + auto-refresh. All charts read these.
    # # Interval is fixed at 2 seconds as requested (editable box defaults to 2).
    st.sidebar.header("Controls")
    range_label = st.sidebar.selectbox("Time range (all time charts)", list(TIME_RANGES.keys()), index=1)
    hours = TIME_RANGES[range_label]
    auto = st.sidebar.checkbox("Auto-refresh (keep updating)", value=True)
    interval = st.sidebar.number_input("Refresh every (seconds)", min_value=2, max_value=300, value=REFRESH_SECONDS, step=1)
    # # Fixed query sizes (sliders removed): top 10 processes, 50 events per query.
    top_n = 10
    event_count = 50
    st.sidebar.caption("JSON files: live_snapshot.json (full) + usb_live.json (USB every 2s)")
    st.sidebar.caption("Full scan is slow (~20s: CPU sampling + software scan). USB runs on its own 2s thread.")
    if st.sidebar.button("Refresh now"):
        st.rerun()
    # # Placeholder holds the visible dashboard. We swap it only when new JSON is ready.
    # # Beginner idea: old picture stays on the wall until the new picture is painted.
    board = st.empty()
    status = st.sidebar.empty()
    # # Prefer the JSON file on disk as the source of truth (survives reruns).
    # # Fall back to session memory only if the file does not exist yet.
    old = load_snapshot_json()
    if old is None:
        old = st.session_state.get("snapshot", None)
    if old is not None:
        # # Step 1: instantly show previous data so the screen never goes blank.
        with board.container():
            render_dashboard(old, hours, range_label)
        status.info("Holding last data... next JSON in " + str(int(interval)) + "s.")
    else:
        # # Very first run: nothing stored yet, show a friendly loader.
        with board.container():
            st.info("Loading first live snapshot from Windows (takes a few seconds)...")
        status.info("First load, please wait...")
    # # Step 2: wait exactly the interval (2 seconds), old data stays visible meanwhile.
    time.sleep(int(interval))
    # # Step 3: prepare the new data, then remake the JSON file on disk.
    # # The old dashboard above stays visible in the browser during this wait.
    fresh = fetch_live_snapshot(top_n, event_count)
    fresh = save_snapshot_json(fresh)
    # # Step 4: reread the JSON file back (dashboard updates FROM the file, not memory).
    from_file = load_snapshot_json()
    if from_file is None:
        from_file = fresh
    # # Step 5: save one history row for the time-range charts.
    try:
        save_snapshot(from_file["summary"]["cpu_total_percent"], from_file["summary"]["ram_percent"], from_file["summary"]["swap_percent"], len(from_file["failed_events"]))
    except Exception:
        pass
    # # Step 6: store and atomically swap to the new dashboard only when JSON is ready.
    st.session_state["snapshot"] = from_file
    status.success("JSON remade + dashboard updated at " + str(from_file.get("updated_at", "")))
    board.empty()
    with board.container():
        render_dashboard(from_file, hours, range_label)
    # # Step 7: start the next cycle. New data stays visible until the next JSON is ready.
    # # Beginner note: st.rerun() restarts main() from the top, old JSON shows first again.
    if auto:
        st.rerun()


# # Streamlit runs main() on every page load/refresh.
if __name__ == "__main__":
    main()
