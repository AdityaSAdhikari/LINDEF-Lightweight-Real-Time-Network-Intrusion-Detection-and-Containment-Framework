"""
LINDEF desktop app: local HTTP API, detection loop, and native window.

    python app/server.py              # opens the desktop window
    python app/server.py --headless   # server only; prints desktop and phone links

The desktop window and any paired phone load the same web UI (web/index.html)
from this server. A phone on the same Wi-Fi joins by scanning the pairing QR
code shown on the desktop. Every /api request must carry the pairing token,
and only the desktop (loopback) can change traffic sources or see the pairing
code. Full API contract: docs/desktop_app_spec.md.
"""

import argparse
import hmac
import ipaddress
import json
import secrets
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import segno

import engine

INDEX_HTML = Path(__file__).resolve().parent / "web" / "index.html"
TOKEN = secrets.token_urlsafe(24)  # ponytail: new token per launch; persist it if re-pairing gets annoying

MAX_LOGS = 500          # session log cap, same as the original dashboard
RECENT_ROWS = 50        # rows shown in the Recent Detections table
DEVICE_TIMEOUT = 30     # seconds before a phone counts as disconnected

DEFAULT_SETTINGS = {
    "mode": "simulation",  # "simulation" or "live"
    "refresh_seconds": 2.0,
    "rows_per_step": 10,
    "simulation_csv": str(engine.DEFAULT_SIMULATION_CSV),
    "tshark_path": "tshark",
    "interface_id": "1",
    "capture_duration": 5,
    "cicflowmeter_command": 'CICFlowMeter.bat "{input}" "{output}"',
}

# (min, max, type) for numeric settings; values outside are clamped.
NUMERIC_LIMITS = {
    "refresh_seconds": (0.5, 10.0, float),
    "rows_per_step": (1, 100, int),
    "capture_duration": (2, 20, int),
}

# Settings that decide where traffic comes from. They feed shell commands and
# file paths, so only the desktop may change them, never a phone.
DESKTOP_ONLY_SETTINGS = {"mode", "simulation_csv", "tshark_path", "interface_id", "cicflowmeter_command"}


def value_counts(series: pd.Series) -> list:
    """Return [[label, count], ...] sorted by count, ready for JSON."""
    return [[str(k), int(v)] for k, v in series.value_counts().items()]


class Monitor:
    """Owns the detection loop and every piece of state the UI reads."""

    def __init__(self):
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.running = False
        self.logs = []
        self.simulation_idx = 0
        self.epoch = 0  # bumped by clear() so a batch already in flight is dropped
        self.last_error = ""
        self.settings = dict(DEFAULT_SETTINGS)
        self.devices = {}  # phone ip -> {"seen": epoch seconds, "agent": user agent}
        self.sim_cache = (None, None, None)  # (path, mtime, DataFrame)

        self.missing_models = engine.missing_model_files()
        self.models = None
        if not self.missing_models:
            self.models = engine.load_models()

    # ----- detection loop -----------------------------------------------------

    def loop(self):
        while True:
            if self.running:
                epoch = self.epoch
                try:
                    self.append(engine.classify_flows(self.next_batch(epoch), self.models), epoch)
                    self.last_error = ""
                except Exception as exc:
                    self.last_error = str(exc) or type(exc).__name__
            self.wake.wait(self.settings_copy()["refresh_seconds"])
            self.wake.clear()

    def settings_copy(self) -> dict:
        with self.lock:
            return dict(self.settings)

    def next_batch(self, epoch: int) -> pd.DataFrame:
        """Read the next chunk of flows from the active traffic source."""
        s = self.settings_copy()

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
            # Wrap around to keep the demo running.
            batch_df = pd.concat([raw_df.iloc[start:], raw_df.iloc[: end % len(raw_df)]], ignore_index=True)

        with self.lock:
            if epoch == self.epoch:
                self.simulation_idx = end % len(raw_df)
        return batch_df

    def simulation_df(self, path: Path) -> pd.DataFrame:
        """Load the simulation CSV, re-reading only when the file changes."""
        if not path.exists():
            raise RuntimeError(f"Simulation CSV not found: {path}")
        mtime = path.stat().st_mtime
        cached_path, cached_mtime, cached_df = self.sim_cache
        if cached_path != path or cached_mtime != mtime:
            cached_df = pd.read_csv(path)
            self.sim_cache = (path, mtime, cached_df)
        if cached_df.empty:
            raise RuntimeError("Simulation CSV is empty.")
        return cached_df

    def append(self, rows: list, epoch: int):
        """Add new detections to the session log and save a copy to disk."""
        with self.lock:
            if not rows or epoch != self.epoch:
                return  # nothing new, or Clear Logs ran while this batch was in flight
            self.logs = (self.logs + rows)[-MAX_LOGS:]
            logs = list(self.logs)
        pd.DataFrame(logs).to_csv(engine.LOG_FILE, index=False)

    # ----- commands -------------------------------------------------------------

    def start(self):
        if self.models is None:
            raise ValueError("Models are not loaded. Add the model files and restart LINDEF.")
        self.running = True
        self.wake.set()  # run the first step now instead of after one refresh period

    def stop(self):
        self.running = False

    def clear(self):
        with self.lock:
            self.logs = []
            self.simulation_idx = 0
            self.epoch += 1
        engine.LOG_FILE.unlink(missing_ok=True)

    def update_settings(self, changes: dict, from_desktop: bool):
        """Validate and apply setting changes. Raises ValueError/PermissionError."""
        clean = {}
        for key, value in changes.items():
            if key not in DEFAULT_SETTINGS:
                raise ValueError(f"Unknown setting: {key}")
            if key in DESKTOP_ONLY_SETTINGS and not from_desktop:
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
                clean[key] = str(value).strip()[:1000]
        with self.lock:
            self.settings.update(clean)
        self.wake.set()  # pick up a new refresh speed right away

    # ----- read-only views -------------------------------------------------------

    def seen(self, ip: str, agent: str):
        with self.lock:
            self.devices[ip] = {"seen": time.time(), "agent": agent}

    def state(self, from_desktop: bool) -> dict:
        """Everything the dashboard needs for one refresh."""
        with self.lock:
            logs_df = pd.DataFrame(self.logs)
            devices = [
                {"ip": ip, "agent": d["agent"], "seconds_ago": round(time.time() - d["seen"])}
                for ip, d in self.devices.items()
                if time.time() - d["seen"] < DEVICE_TIMEOUT
            ]

        state = {
            "running": self.running,
            "error": self.last_error,
            "settings": self.settings_copy(),
            "desktop": from_desktop,
            "models": {"loaded": self.models is not None, "missing": self.missing_models},
            "metrics": {"total": 0, "attacks": 0, "benign": 0, "latest": "Waiting"},
            "recent": [],
            "charts": {"status": [], "severity": [], "attacks": [], "responses": []},
        }
        if from_desktop:
            state["devices"] = devices

        if logs_df.empty:
            return state

        state["metrics"] = {
            "total": len(logs_df),
            "attacks": int((logs_df["Status"] == "ATTACK").sum()),
            "benign": int((logs_df["Status"] == "BENIGN").sum()),
            "latest": logs_df.iloc[-1]["Status"],
        }
        recent = logs_df.tail(RECENT_ROWS).astype(object)
        state["recent"] = recent.where(recent.notna(), None).to_dict("records")
        state["charts"] = {
            "status": value_counts(logs_df["Status"]),
            "severity": value_counts(logs_df["Severity"]),
            "attacks": value_counts(logs_df.loc[logs_df["Attack"] != "normal", "Attack"]),
            "responses": value_counts(logs_df["Response"]),
        }
        return state

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
        with self.lock:
            return pd.DataFrame(self.logs).to_csv(index=False)


def lan_ip() -> str:
    """Best guess at this machine's Wi-Fi/LAN address (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def make_handler(monitor: Monitor, port: int):
    phone_url = f"http://{lan_ip()}:{port}/#t={TOKEN}"

    class Handler(BaseHTTPRequestHandler):
        server_version = "LINDEF"

        def log_message(self, *args):
            pass  # keep the terminal quiet; errors surface in the UI

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

        def from_desktop(self) -> bool:
            return ipaddress.ip_address(self.client_address[0]).is_loopback

        def authorized(self) -> bool:
            token = self.headers.get("X-Lindef-Token", "")
            if not hmac.compare_digest(token.encode(), TOKEN.encode()):
                self.send_json(401, {"error": "Not paired. Scan the QR code in the desktop app."})
                return False
            if not self.from_desktop():
                monitor.seen(self.client_address[0], self.headers.get("User-Agent", "")[:200])
            return True

        def read_json(self) -> dict:
            length = min(int(self.headers.get("Content-Length") or 0), 64_000)
            if not length:
                return {}
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object.")
            return data

        # ----- routes ---------------------------------------------------------

        def do_GET(self):
            path = urlparse(self.path).path

            if path in ("/", "/index.html"):
                return self.send(200, INDEX_HTML.read_bytes(), "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.send_json(404, {"error": "Not found."})
            if not self.authorized():
                return

            if path == "/api/state":
                return self.send_json(200, monitor.state(self.from_desktop()))
            if path == "/api/model":
                return self.send_json(200, monitor.model_info())
            if path == "/api/log.csv":
                return self.send(200, monitor.log_csv().encode(), "text/csv; charset=utf-8",
                                 {"Content-Disposition": 'attachment; filename="attack_log.csv"'})
            if path == "/api/pair":
                if not self.from_desktop():
                    return self.send_json(403, {"error": "Pairing is only available on the desktop."})
                qr = segno.make(phone_url, error="m")
                return self.send_json(200, {"url": phone_url, "svg": qr.svg_inline(scale=5, border=2)})
            return self.send_json(404, {"error": "Not found."})

        def do_POST(self):
            path = urlparse(self.path).path
            if not path.startswith("/api/"):
                return self.send_json(404, {"error": "Not found."})
            if not self.authorized():
                return
            try:
                if path == "/api/start":
                    monitor.start()
                elif path == "/api/stop":
                    monitor.stop()
                elif path == "/api/clear":
                    monitor.clear()
                elif path == "/api/settings":
                    monitor.update_settings(self.read_json(), self.from_desktop())
                else:
                    return self.send_json(404, {"error": "Not found."})
            except PermissionError as exc:
                return self.send_json(403, {"error": str(exc)})
            except ValueError as exc:  # json.JSONDecodeError is a ValueError too
                return self.send_json(400, {"error": str(exc)})
            return self.send_json(200, monitor.state(self.from_desktop()))

    return Handler, phone_url


def main():
    parser = argparse.ArgumentParser(description="LINDEF desktop app")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--headless", action="store_true", help="run the server without opening a window")
    args = parser.parse_args()

    monitor = Monitor()
    handler, phone_url = make_handler(monitor, args.port)
    try:
        # 0.0.0.0 so phones on the same network can reach it; the token guards access.
        httpd = ThreadingHTTPServer(("0.0.0.0", args.port), handler)
    except OSError as exc:
        sys.exit(f"Could not open port {args.port} ({exc}). Try: python app/server.py --port 8766")

    threading.Thread(target=monitor.loop, daemon=True).start()
    desktop_url = f"http://127.0.0.1:{args.port}/#t={TOKEN}"

    if monitor.missing_models:
        print("Missing model files (the app opens, but detection stays off):")
        for path in monitor.missing_models:
            print("  " + path)

    try:
        import webview
    except ImportError:
        webview = None

    if args.headless or webview is None:
        print(f"Desktop: {desktop_url}")
        print(f"Phone:   {phone_url}")
        segno.make(phone_url, error="m").terminal(compact=True)
        if webview is None and not args.headless:
            import webbrowser
            webbrowser.open(desktop_url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nLINDEF stopped.")
        return

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    webview.settings["ALLOW_DOWNLOADS"] = True  # lets "Download Detection Log" save the CSV
    webview.create_window("LINDEF", desktop_url, width=1320, height=880, min_size=(960, 640))
    webview.start()  # blocks until the window closes; daemon threads exit with it


if __name__ == "__main__":
    main()
