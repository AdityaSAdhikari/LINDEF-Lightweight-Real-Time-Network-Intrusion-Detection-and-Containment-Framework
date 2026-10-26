"""
LINDEF agent: runs on the server being defended.

    python app/agent.py                          # simulation mode, port 9443
    python app/agent.py --tshark /usr/bin/tshark --interface eth0 \
        --cicflowmeter 'cicflowmeter -f "{input}" -c "{output}/flows.csv"'
    python app/agent.py --pair phone             # print a phone pairing code too
    python app/agent.py --reset                  # new certificate; unpair every device

The agent captures and classifies traffic with engine.py and serves the
results over HTTPS. The desktop app and phone apps each connect to it
directly; there is no relay between them. On first start it prints a desktop
pairing code. A paired desktop can then create phone pairing codes.

Traffic-source commands and paths (TShark, CICFlowMeter, simulation CSV) are
set only here, with command-line flags. No device can change them over the
network, so a stolen device token cannot run commands on this server.
Full API contract: docs/desktop_app_spec.md.
"""

import argparse
import csv
import json
import secrets
import socket
import sys
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pandas as pd
import segno

import engine
import secure

VERSION = "2.0"
DEFAULT_PORT = 9443
DEFAULT_DATA_DIR = "~/.lindef/agent"

MAX_LOGS = 500              # detections kept in memory; counts and attack_log.csv keep everything
RECENT_ROWS = 50            # rows in the Recent Detections table
PAIR_CODE_SECONDS = 600     # pairing codes are single use and expire after 10 minutes
ONLINE_SECONDS = 30         # a device counts as online this long after its last request

ROLES = ("desktop", "phone")

# Settings devices may change over the API: (min, max, type), values clamped.
NUMERIC_LIMITS = {
    "refresh_seconds": (0.5, 10.0, float),
    "rows_per_step": (1, 100, int),
    "capture_duration": (2, 20, int),
}
DESKTOP_ONLY_SETTINGS = {"mode"}

# Settings that feed shell commands or file paths: command-line flags only.
LOCAL_ONLY_SETTINGS = {
    "simulation_csv": "--simulation-csv",
    "tshark_path": "--tshark",
    "interface_id": "--interface",
    "cicflowmeter_command": "--cicflowmeter",
}


# Simulated containment: how long each action lasts (None would mean until lifted).
# Repeat attacks renew the timer; the desktop can lift any action early.
CONTAINMENT_SECONDS = {"BLOCK_IP": 15 * 60, "THROTTLE_IP": 10 * 60, "ISOLATE_HOST": 10 * 60}
CONTAINED_LABEL = {"BLOCK_IP": "BLOCKED", "THROTTLE_IP": "THROTTLED", "ISOLATE_HOST": "ISOLATED"}
ACTION_VERB = {"BLOCK_IP": "Blocked", "THROTTLE_IP": "Throttled", "ISOLATE_HOST": "Isolated Host"}
MAX_ACTIONS = 200           # containment history kept
MAX_NOTIFICATIONS = 200     # notification feed kept
ATTACK_NOTE_SECONDS = 60    # at most one "attack detected" note per attack type per minute
NOTIFY_SEVERITIES = {"HIGH", "CRITICAL", "UNKNOWN"}  # uncontained attacks worth a notification

# Simulation CSVs (like simulation_test.csv) carry no addresses. In simulation
# mode the agent assigns them after classification, from reserved ranges only:
# attacks come from the RFC 5737 documentation ranges, benign traffic from
# thousands of clients (198.18.0.0/15, RFC 2544), and both go to defended hosts
# in 10.0.0.0/23. Neighbouring rows share an attacker (a burst comes from one or
# two sources), and every pass through the CSV brings new attackers, so blocks
# expire and new ones start the way they would on a real network.
SIM_ATTACKERS = [f"203.0.113.{n}" for n in range(1, 255)] + [f"198.51.100.{n}" for n in range(1, 255)]
SIM_ATTACKER_ROWS = 50  # rows in a row that share one attacker
SIM_HOSTS = [f"10.0.{n // 254}.{n % 254 + 1}" for n in range(400)]  # isolating one host cuts off a sliver of traffic
SIM_PORTS = [443, 80, 22, 21, 25, 3389, 445, 3306]


def has_address_columns(df: pd.DataFrame) -> bool:
    columns = {str(c).strip() for c in df.columns}
    return any(c in columns for names in engine.ENDPOINT_COLUMNS.values() for c in names)


def add_simulated_addresses(rows: list, positions: list):
    """Give classified simulation rows made-up addresses (see SIM_ATTACKERS).
    positions count rows since monitoring started, across passes through the CSV."""
    for row, position in zip(rows, positions):
        mix = (int(position) * 2654435761) % 2**32  # scatter neighbouring rows
        if row["Status"] == "ATTACK":
            group = ((int(position) // SIM_ATTACKER_ROWS) * 2654435761) % 2**32
            row["Source IP"] = SIM_ATTACKERS[(group >> 5) % len(SIM_ATTACKERS)]
        else:
            row["Source IP"] = f"198.{18 + (mix >> 24) % 2}.{(mix >> 8) % 256}.{mix % 254 + 1}"
        row["Source Port"] = str(49152 + (mix >> 12) % 16000)
        row["Destination IP"] = SIM_HOSTS[(mix >> 4) % len(SIM_HOSTS)]
        row["Destination Port"] = str(SIM_PORTS[(mix >> 16) % len(SIM_PORTS)])


class Containment:
    """Simulated firewall. Records what LINDEF would block, throttle, or isolate,
    and marks later flows it would have stopped. It never changes real traffic.

    Not thread-safe on its own: Monitor calls it while holding its lock.
    """

    def __init__(self):
        self.actions = []   # oldest first
        self.next_id = 1

    def active(self, now: float) -> dict:
        """Expire finished actions, then return {(action, target): record} for live ones."""
        live = {}
        for a in self.actions:
            if a["active"] and a["expires"] is not None and a["expires"] <= now:
                a.update(active=False, ended="expired", ended_at=int(now))
            if a["active"]:
                live[(a["action"], a["target"])] = a
        return live

    def apply(self, rows: list, now: float) -> list:
        """Mark rows the simulated firewall would stop; start or extend actions.
        Returns the actions started by this batch."""
        live = self.active(now)
        started = []
        for row in rows:
            source, host = row.get("Source IP"), row.get("Destination IP")
            stopped_by = (live.get(("BLOCK_IP", source)) or live.get(("ISOLATE_HOST", host))
                          or live.get(("THROTTLE_IP", source)))
            row["Contained"] = CONTAINED_LABEL[stopped_by["action"]] if stopped_by else None
            if stopped_by:
                stopped_by["flows_stopped"] += 1

            action = row["Response"]
            if row["Status"] != "ATTACK" or action not in CONTAINMENT_SECONDS:
                continue
            target = host if action == "ISOLATE_HOST" else source
            if not target:
                continue  # no address to act on (live capture without IP columns)
            seconds = CONTAINMENT_SECONDS[action]
            existing = live.get((action, target))
            if existing:  # repeat offender: extend instead of starting a new action
                existing["triggers"] += 1
                existing["last_attack"] = row["Attack"]
                if seconds:
                    existing["expires"] = int(now + seconds)
                continue
            record = {
                "id": self.next_id, "action": action, "target": target,
                "target_kind": "host" if action == "ISOLATE_HOST" else "source",
                "attack": row["Attack"], "last_attack": row["Attack"], "severity": row["Severity"],
                "detection_id": row["ID"], "started": int(now),
                "expires": int(now + seconds) if seconds else None,
                "triggers": 1, "flows_stopped": 0, "active": True,
                "ended": None, "ended_at": None, "ended_by": None, "simulated": True,
            }
            self.next_id += 1
            self.actions.append(record)
            live[(action, target)] = record
            started.append(record)
        self.actions = self.actions[-MAX_ACTIONS:]
        return started

    def lift(self, action_id: int, by: str, now: float) -> dict:
        self.active(now)
        for a in self.actions:
            if a["id"] == action_id and a["active"]:
                a.update(active=False, ended="lifted", ended_at=int(now), ended_by=by)
                return a
        raise KeyError(action_id)

    def lift_all(self, by: str, now: float):
        for a in self.active(now).values():
            a.update(active=False, ended="cleared", ended_at=int(now), ended_by=by)

    def summary(self, now: float) -> dict:
        live = self.active(now)
        return {
            "enforcement": "simulated",
            "active": sorted((dict(a) for a in live.values()), key=lambda a: -a["started"]),
            "history": [dict(a) for a in reversed(self.actions[-50:])],
            "flows_stopped": sum(a["flows_stopped"] for a in self.actions),
        }


# -----------------------------------------------------------------------------
# Detection loop
# -----------------------------------------------------------------------------

class Monitor:
    """Owns the detection loop and the session log."""

    def __init__(self, sources: dict):
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.running = False
        self.logs = []
        self.counts = self.empty_counts()  # running totals since the last Clear Logs
        self.recent_attacks = deque(maxlen=10)  # for Threats at Hand; the flow log scrolls past attacks in seconds
        self.next_id = 1           # every detection gets an ID; IDs never repeat, even after Clear
        self.simulation_idx = 0
        self.epoch = 0             # bumped by clear() so a batch already in flight is dropped
        self.last_error = ""
        self.settings = {"mode": "simulation", "refresh_seconds": 2.0, "rows_per_step": 10,
                         "capture_duration": 5, **sources}
        self.sim_cache = (None, None, None)  # (path, mtime, DataFrame)
        self.simulated_addresses = False
        self.sim_positions = None  # row counts of the current batch, when addresses are simulated
        self.sim_rows_sent = 0     # simulation rows sent since the last Clear Logs (keeps growing past the CSV)
        self.containment = Containment()
        self.notifications = []
        self.next_note_id = 1
        self.last_attack_note = {}  # attack name -> time of its last "attack detected" note

        self.missing_models = engine.missing_model_files()
        self.models = None
        if not self.missing_models:
            self.models = engine.load_models()

    def loop(self):
        while True:
            if self.running:
                epoch = self.epoch
                try:
                    batch = self.next_batch(epoch)
                    rows = engine.classify_flows(batch, self.models)
                    if self.sim_positions is not None:
                        add_simulated_addresses(rows, self.sim_positions)
                    self.append(rows, epoch)
                    self.last_error = ""
                except Exception as exc:
                    error = str(exc) or type(exc).__name__
                    if error != self.last_error:  # notify once per new problem, not every cycle
                        with self.lock:
                            self.notify("error", "HIGH", "Detection Stopped Working", error.splitlines()[0])
                    self.last_error = error
            self.wake.wait(self.settings_copy()["refresh_seconds"])
            self.wake.clear()

    def settings_copy(self) -> dict:
        with self.lock:
            return dict(self.settings)

    def next_batch(self, epoch: int) -> pd.DataFrame:
        """Read the next chunk of flows from the active traffic source."""
        s = self.settings_copy()

        self.sim_positions = None
        if s["mode"] == "live":
            pcap_path = engine.capture_pcap(s["tshark_path"], s["interface_id"], s["capture_duration"])
            csv_path = engine.run_cicflowmeter(s["cicflowmeter_command"], pcap_path)
            try:
                return pd.read_csv(csv_path)
            except pd.errors.EmptyDataError:
                return pd.DataFrame()  # quiet network: no flows in this capture
            finally:
                # The CSV is derived from the pcap (which is kept). Deleting it stops
                # the "newest CSV" fallback from re-reading the same flows next cycle.
                csv_path.unlink(missing_ok=True)

        raw_df = self.simulation_df(Path(s["simulation_csv"]))
        start = self.simulation_idx
        end = start + s["rows_per_step"]

        if end <= len(raw_df):
            batch_df = raw_df.iloc[start:end]
        else:
            # Wrap around to keep the simulation running.
            batch_df = pd.concat([raw_df.iloc[start:], raw_df.iloc[: end % len(raw_df)]], ignore_index=True)
        self.simulated_addresses = not has_address_columns(raw_df)
        if self.simulated_addresses:
            self.sim_positions = [self.sim_rows_sent + i for i in range(len(batch_df))]
            self.sim_rows_sent += len(batch_df)

        with self.lock:
            if epoch == self.epoch:
                self.simulation_idx = end % len(raw_df)
        return batch_df

    def simulation_df(self, path: Path) -> pd.DataFrame:
        """Load the simulation CSV, re-reading only when the file changes."""
        if not path.exists():
            raise RuntimeError(f"Simulation CSV not found on the server: {path}")
        mtime = path.stat().st_mtime
        cached_path, cached_mtime, cached_df = self.sim_cache
        if cached_path != path or cached_mtime != mtime:
            cached_df = pd.read_csv(path)
            self.sim_cache = (path, mtime, cached_df)
        if cached_df.empty:
            raise RuntimeError("Simulation CSV is empty.")
        return cached_df

    def append(self, rows: list, epoch: int):
        """Number new detections, run simulated containment, raise notifications,
        add them to the session log, and save a copy to disk."""
        now = time.time()
        with self.lock:
            if not rows or epoch != self.epoch:
                return  # nothing new, or Clear Logs ran while this batch was in flight
            rows = [{"ID": self.next_id + i, **row} for i, row in enumerate(rows)]
            self.next_id += len(rows)
            started = self.containment.apply(rows, now)
            self.logs = (self.logs + rows)[-MAX_LOGS:]
            for row in rows:
                c = self.counts
                c["status"][row["Status"]] += 1
                c["severity"][row["Severity"]] += 1
                c["responses"][row["Response"]] += 1
                if row["Status"] == "ATTACK":
                    c["attacks"][row["Attack"]] += 1
                    self.recent_attacks.append(row)
                if row["Contained"]:
                    c["contained"] += 1

            for a in started:
                lasts = (f"Lasts {CONTAINMENT_SECONDS[a['action']] // 60} minutes unless repeated."
                         if a["expires"] else "Lasts until lifted from the desktop.")
                self.notify("containment", a["severity"], f"{ACTION_VERB[a['action']]} {a['target']} (Simulated)",
                            f"{engine.attack_label(a['attack'])} attack, {a['severity'].lower()} severity. No real traffic was "
                            f"changed. {lasts}", action_id=a["id"], detection_id=a["detection_id"])
            triggered = {a["detection_id"] for a in started}
            for row in rows:
                if (row["Status"] == "ATTACK" and row["Severity"] in NOTIFY_SEVERITIES
                        and row["ID"] not in triggered and row["Contained"] is None
                        and row["Response"] not in CONTAINMENT_SECONDS
                        and now - self.last_attack_note.get(row["Attack"], 0) >= ATTACK_NOTE_SECONDS):
                    self.last_attack_note[row["Attack"]] = now
                    route = f" from {row['Source IP']} to {row['Destination IP']}" if row.get("Source IP") else ""
                    self.notify("attack", row["Severity"], f"Attack Detected: {engine.attack_label(row['Attack'])}",
                                f"{row['Severity'].capitalize()} severity{route}. "
                                f"Recommended response: {engine.response_label(row['Response'])}.", detection_id=row["ID"])
        new_file = not engine.LOG_FILE.exists()
        with open(engine.LOG_FILE, "a", newline="") as f:  # grows for the whole session
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            if new_file:
                writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def empty_counts() -> dict:
        return {"status": Counter(), "severity": Counter(), "attacks": Counter(),
                "responses": Counter(), "contained": 0}

    def notify(self, kind: str, severity: str, title: str, body: str, action_id=None, detection_id=None):
        """Add to the notification feed. Call while holding self.lock."""
        self.notifications.append({
            "id": self.next_note_id, "time": int(time.time()), "kind": kind, "severity": severity,
            "title": title, "body": body, "action_id": action_id, "detection_id": detection_id,
        })
        self.next_note_id += 1
        self.notifications = self.notifications[-MAX_NOTIFICATIONS:]

    # ----- commands -------------------------------------------------------------

    def start(self):
        if self.models is None:
            raise ValueError("Models are not loaded on the server. Add the model files and restart the agent.")
        self.running = True
        self.wake.set()  # run the first step now instead of after one refresh period

    def stop(self):
        self.running = False

    def clear(self, by: str):
        """Empty the detection log and lift all simulated containment (a fresh start)."""
        with self.lock:
            self.logs = []
            self.counts = self.empty_counts()
            self.recent_attacks.clear()
            self.simulation_idx = 0
            self.sim_rows_sent = 0
            self.epoch += 1
            self.containment.lift_all(by, time.time())
        engine.LOG_FILE.unlink(missing_ok=True)

    def lift(self, action_id: int, by: str) -> dict:
        with self.lock:
            action = dict(self.containment.lift(action_id, by, time.time()))
            self.notify("containment", "NONE", f"Lifted: {ACTION_VERB[action['action']]} "
                        f"{action['target']} (Simulated)", f"Lifted by {by}.", action_id=action_id)
        return action

    def update_settings(self, changes: dict, role: str):
        """Validate and apply setting changes. Raises ValueError/PermissionError."""
        clean = {}
        for key, value in changes.items():
            if key in LOCAL_ONLY_SETTINGS:
                raise PermissionError(f"'{key}' is set on the server itself: restart the agent with "
                                      f"{LOCAL_ONLY_SETTINGS[key]}.")
            if key in DESKTOP_ONLY_SETTINGS and role != "desktop":
                raise PermissionError(f"'{key}' can only be changed from the desktop app.")
            if key in NUMERIC_LIMITS:
                low, high, cast = NUMERIC_LIMITS[key]
                try:
                    clean[key] = min(high, max(low, cast(value)))
                except (TypeError, ValueError):
                    raise ValueError(f"'{key}' must be a number.")
            elif key == "mode":
                if value not in ("simulation", "live"):
                    raise ValueError("mode must be 'simulation' or 'live'.")
                clean[key] = value
            else:
                raise ValueError(f"Unknown setting: {key}")
        with self.lock:
            self.settings.update(clean)
        self.wake.set()  # pick up a new refresh speed right away

    # ----- read-only views ----------------------------------------------------

    def state(self) -> dict:
        """Everything a dashboard needs for one refresh."""
        with self.lock:
            logs_df = pd.DataFrame(self.logs[-RECENT_ROWS:])
            c = {k: (v.copy() if isinstance(v, Counter) else v) for k, v in self.counts.items()}
            recent_attacks = list(self.recent_attacks)
            last_id = self.next_id - 1
            epoch = self.epoch
            containment = self.containment.summary(time.time())
            notifications_last_id = self.next_note_id - 1

        state = {
            "running": self.running,
            "error": self.last_error,
            "settings": self.settings_copy(),
            "models": {"loaded": self.models is not None, "missing": self.missing_models},
            "simulated_addresses": self.simulated_addresses,
            "last_id": last_id,
            "epoch": epoch,
            "notifications_last_id": notifications_last_id,
            "metrics": {"total": 0, "attacks": 0, "benign": 0, "contained": 0, "latest": "Waiting"},
            "containment": containment,
            "recent": [],
            "recent_attacks": recent_attacks,
            "charts": {"status": [], "severity": [], "attacks": [], "responses": []},
            "labels": {"attacks": engine.ATTACK_LABELS, "responses": engine.RESPONSE_LABELS},
        }
        if logs_df.empty:
            return state

        state["metrics"] = {
            "total": sum(c["status"].values()),
            "attacks": c["status"]["ATTACK"],
            "benign": c["status"]["BENIGN"],
            "contained": c["contained"],
            "latest": logs_df.iloc[-1]["Status"],
        }
        recent = logs_df.astype(object)
        state["recent"] = recent.where(recent.notna(), None).to_dict("records")
        state["charts"] = {key: [[k, v] for k, v in c[key].most_common()]
                           for key in ("status", "severity", "attacks", "responses")}
        return state

    def detections(self, after: int, limit: int) -> dict:
        """Detections with ID > after, oldest first. Lets apps fetch only what is new."""
        with self.lock:
            records = [row for row in self.logs if row["ID"] > after][:limit]
            return {"records": records, "last_id": self.next_id - 1, "epoch": self.epoch}

    def notifications_after(self, after: int, limit: int) -> dict:
        with self.lock:
            notes = [n for n in self.notifications if n["id"] > after][:limit]
            return {"notifications": notes, "last_id": self.next_note_id - 1}

    def containment_view(self) -> dict:
        with self.lock:
            return self.containment.summary(time.time())

    def model_info(self) -> dict:
        info = {
            "binary_model": str(engine.BINARY_MODEL_PATH),
            "multi_model": str(engine.MULTI_MODEL_PATH),
            "scaler": str(engine.SCALER_PATH),
            "loaded": self.models is not None,
            "missing": self.missing_models,
            "feature_count": 0,
            "medians_loaded": False,
            "feature_columns": [],
        }
        if self.models:
            info["feature_count"] = len(self.models["feature_columns"])
            info["medians_loaded"] = self.models["feature_medians"] is not None
            info["feature_columns"] = self.models["feature_columns"]
        return info

    def log_csv(self) -> str:
        """The whole session's detections (attack_log.csv)."""
        with self.lock:
            return engine.LOG_FILE.read_text() if engine.LOG_FILE.exists() else ""


# -----------------------------------------------------------------------------
# Paired devices
# -----------------------------------------------------------------------------

class Devices:
    """Paired desktops and phones. Each has its own token, stored only as a hash."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.devices = secure.read_json(path, {})  # id -> {name, role, token_hash, paired_at}
        self.codes = {}                             # pairing code -> {"role", "expires"}
        self.last_seen = {}                         # id -> {"time", "ip"} (memory only)

    def save(self):
        secure.write_json(self.path, self.devices)

    def issue_code(self, role: str) -> str:
        if role not in ROLES:
            raise ValueError(f"role must be one of: {', '.join(ROLES)}")
        code = secrets.token_urlsafe(16)
        with self.lock:
            now = time.time()
            self.codes = {c: v for c, v in self.codes.items() if v["expires"] > now}  # drop expired
            self.codes[code] = {"role": role, "expires": now + PAIR_CODE_SECONDS}
        return code

    def claim(self, code: str, name: str) -> dict:
        """Trade a pairing code for a device token. Each code works once."""
        with self.lock:
            match = next((c for c in self.codes if secure.secrets_match(c, str(code))), None)
            if match is None or self.codes[match]["expires"] < time.time():
                raise PermissionError("That pairing code is wrong or expired. Make a new one and try again.")
            role = self.codes.pop(match)["role"]
            device_id = secrets.token_hex(6)
            token = secrets.token_urlsafe(32)
            self.devices[device_id] = {
                "name": str(name).strip()[:80] or role.capitalize(),
                "role": role,
                "token_hash": secure.hash_secret(token),
                "paired_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            self.save()
        return {"device_id": device_id, "role": role, "token": token}

    def authenticate(self, token: str, ip: str) -> tuple[str, dict] | None:
        token_hash = secure.hash_secret(token)
        with self.lock:
            for device_id, device in self.devices.items():
                if secure.secrets_match(device["token_hash"], token_hash):
                    self.last_seen[device_id] = {"time": time.time(), "ip": ip}
                    return device_id, device
        return None

    def revoke(self, device_id: str):
        with self.lock:
            if self.devices.pop(device_id, None) is None:
                raise KeyError(device_id)
            self.last_seen.pop(device_id, None)
            self.save()

    def has_role(self, role: str) -> bool:
        with self.lock:
            return any(d["role"] == role for d in self.devices.values())

    def listing(self) -> list:
        now = time.time()
        with self.lock:
            rows = []
            for device_id, device in self.devices.items():
                seen = self.last_seen.get(device_id)
                rows.append({
                    "device_id": device_id,
                    "name": device["name"],
                    "role": device["role"],
                    "paired_at": device["paired_at"],
                    "online": bool(seen) and now - seen["time"] < ONLINE_SECONDS,
                    "last_seen_seconds": round(now - seen["time"]) if seen else None,
                    "ip": seen["ip"] if seen else None,
                })
            return rows


# -----------------------------------------------------------------------------
# HTTPS API
# -----------------------------------------------------------------------------

def make_handler(monitor: Monitor, devices: Devices, pairing_code):
    """pairing_code(code) -> the full lindef:// string a device scans or pastes."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "LINDEF-agent"

        def log_message(self, *args):
            pass  # keep the terminal quiet; errors reach the apps

        # ----- helpers --------------------------------------------------------

        def send(self, status: int, body: bytes, content_type: str, extra_headers=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status: int, payload):
            self.send(status, json.dumps(payload, allow_nan=False).encode(), "application/json")

        def read_json(self) -> dict:
            if not self.raw_body:
                return {}
            data = json.loads(self.raw_body)
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object.")
            return data

        def caller(self):
            """Return (device_id, device) for a valid token, else send 401 and return None."""
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else ""
            found = devices.authenticate(token, self.client_address[0]) if token else None
            if found is None:
                self.send_json(401, {"error": "This device is not paired with the LINDEF server."})
            return found

        def query_int(self, name: str, default: int, low: int, high: int) -> int:
            values = parse_qs(urlparse(self.path).query).get(name)
            if not values:
                return default
            return min(high, max(low, int(values[0])))  # ValueError -> 400

        # ----- routes ---------------------------------------------------------

        def do_GET(self):
            self.route("GET")

        def do_POST(self):
            self.route("POST")

        def do_DELETE(self):
            self.route("DELETE")

        def route(self, method: str):
            path = urlparse(self.path).path
            # Read the body before any reply, even a refusal: closing a socket with
            # unread data makes the client see a connection reset instead of the error.
            try:
                length = max(0, int(self.headers.get("Content-Length") or 0))
            except ValueError:
                return self.send_json(400, {"error": "Bad Content-Length."})
            if length > 64_000:
                self.close_connection = True
                return self.send_json(413, {"error": "Request body too large."})
            self.raw_body = self.rfile.read(length)
            try:
                if (method, path) == ("POST", "/v1/pair/claim"):
                    body = self.read_json()
                    return self.send_json(200, devices.claim(body.get("code", ""), body.get("name", "")))

                if not path.startswith("/v1/"):
                    return self.send_json(404, {"error": "Not found."})
                found = self.caller()
                if found is None:
                    return
                device_id, device = found
                role = device["role"]

                if method == "GET":
                    if path == "/v1/health":
                        return self.send_json(200, {
                            "version": VERSION,
                            "server": socket.gethostname(),
                            "running": monitor.running,
                            "models_loaded": monitor.models is not None,
                            "device_id": device_id,
                            "device_name": device["name"],
                            "role": role,
                        })
                    if path == "/v1/state":
                        return self.send_json(200, monitor.state())
                    if path == "/v1/detections":
                        after = self.query_int("after", 0, 0, 2**62)
                        limit = self.query_int("limit", 200, 1, MAX_LOGS)
                        return self.send_json(200, monitor.detections(after, limit))
                    if path == "/v1/model":
                        return self.send_json(200, monitor.model_info())
                    if path == "/v1/log.csv":
                        return self.send(200, monitor.log_csv().encode(), "text/csv; charset=utf-8",
                                         {"Content-Disposition": 'attachment; filename="attack_log.csv"'})
                    if path == "/v1/notifications":
                        after = self.query_int("after", 0, 0, 2**62)
                        limit = self.query_int("limit", 100, 1, MAX_NOTIFICATIONS)
                        return self.send_json(200, monitor.notifications_after(after, limit))
                    if path == "/v1/containment":
                        return self.send_json(200, monitor.containment_view())
                    if path == "/v1/devices":
                        self.require_desktop(role)
                        return self.send_json(200, {"devices": devices.listing()})

                if method == "POST":
                    if path == "/v1/start":
                        monitor.start()
                    elif path == "/v1/stop":
                        monitor.stop()
                    elif path == "/v1/clear":
                        monitor.clear(device["name"])
                    elif path == "/v1/settings":
                        monitor.update_settings(self.read_json(), role)
                    elif path.startswith("/v1/containment/") and path.endswith("/lift"):
                        if role != "desktop":
                            raise PermissionError("Only the desktop app can lift containment.")
                        try:
                            action_id = int(path.split("/")[3])
                        except ValueError:
                            raise KeyError(path)
                        lifted = monitor.lift(action_id, device["name"])
                        return self.send_json(200, {**monitor.containment_view(), "lifted": lifted})
                    elif path == "/v1/pair":
                        self.require_desktop(role)
                        code = devices.issue_code(self.read_json().get("role", "phone"))
                        link = pairing_code(code)
                        return self.send_json(200, {
                            "code": link,
                            "qr": segno.make(link, error="m").svg_data_uri(scale=5, border=2),
                            "expires_in": PAIR_CODE_SECONDS,
                        })
                    else:
                        return self.send_json(404, {"error": "Not found."})
                    return self.send_json(200, monitor.state())

                if method == "DELETE" and path.startswith("/v1/devices/"):
                    self.require_desktop(role)
                    devices.revoke(path.rsplit("/", 1)[1])
                    return self.send_json(200, {"devices": devices.listing()})

                return self.send_json(404, {"error": "Not found."})

            except PermissionError as exc:
                return self.send_json(403, {"error": str(exc)})
            except KeyError:
                return self.send_json(404, {"error": "Nothing active has that ID. It may have expired."})
            except ValueError as exc:  # bad JSON, bad numbers, bad role
                return self.send_json(400, {"error": str(exc) or "Bad request."})

        def require_desktop(self, role: str):
            if role != "desktop":
                raise PermissionError("Only the desktop app can manage paired devices.")

    return Handler


# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------

def print_pairing(role: str, link: str):
    print(f"\nPair a {role}: paste or scan this code within {PAIR_CODE_SECONDS // 60} minutes.")
    print(f"  {link}")
    segno.make(link, error="m").terminal(compact=True)


def main():
    parser = argparse.ArgumentParser(description="LINDEF agent for the server being defended")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--bind", default="0.0.0.0", help="address to listen on")
    parser.add_argument("--advertise", help="host name or IP devices should use (default: this machine's LAN IP)")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="where the certificate and paired devices are kept")
    parser.add_argument("--simulation-csv", default=str(engine.DEFAULT_SIMULATION_CSV))
    parser.add_argument("--tshark", default="tshark", help="TShark executable")
    parser.add_argument("--interface", default="1", help="capture interface (see: tshark -D)")
    parser.add_argument("--cicflowmeter", default='CICFlowMeter.bat "{input}" "{output}"',
                        help="CICFlowMeter command; {input} = pcap path, {output} = CSV folder")
    parser.add_argument("--pair", choices=ROLES, action="append", default=[],
                        help="print a pairing code for this kind of device on start")
    parser.add_argument("--reset", action="store_true", help="new certificate and unpair every device")
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)  # show pairing codes at once, even when output goes to a log file

    data_dir = secure.private_dir(args.data_dir)
    if args.reset:
        secure.reset_identity(data_dir)
        (data_dir / "devices.json").unlink(missing_ok=True)
        print("Reset: new certificate created and all devices unpaired.")
    cert_path, key_path, fingerprint = secure.load_or_create_identity(data_dir)

    monitor = Monitor({
        "simulation_csv": args.simulation_csv,
        "tshark_path": args.tshark,
        "interface_id": args.interface,
        "cicflowmeter_command": args.cicflowmeter,
    })
    devices = Devices(data_dir / "devices.json")
    host = args.advertise or secure.lan_ip()

    def pairing_code(code: str) -> str:
        return secure.make_pairing_code(host, args.port, fingerprint, pair=code)

    try:
        httpd = secure.TLSServer((args.bind, args.port), make_handler(monitor, devices, pairing_code),
                                 cert_path, key_path)
    except OSError as exc:
        sys.exit(f"Could not open port {args.port} ({exc}). Try: python app/agent.py --port {args.port + 1}")

    threading.Thread(target=monitor.loop, daemon=True).start()

    print(f"LINDEF agent {VERSION} listening on {host}:{args.port}")
    print(f"Certificate fingerprint: {fingerprint}")
    if monitor.missing_models:
        print("Missing model files (the agent runs, but detection stays off):")
        for path in monitor.missing_models:
            print("  " + path)

    roles = list(dict.fromkeys(args.pair))
    if not devices.has_role("desktop") and "desktop" not in roles:
        roles.insert(0, "desktop")  # first run: nothing can pair phones until a desktop is paired
    for role in roles:
        print_pairing(role, pairing_code(devices.issue_code(role)))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nLINDEF agent stopped.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as exc:
        # Opened by double-click (packaged program): keep the window up so the error can be read.
        if getattr(sys, "frozen", False) and exc.code not in (None, 0):
            print(exc.code)
            input("Press Enter to close.")
            raise SystemExit(1)
        raise
