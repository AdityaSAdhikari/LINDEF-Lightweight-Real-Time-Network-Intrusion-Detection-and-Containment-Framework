"""
LINDEF desktop app: native window plus a secure link to the LINDEF agent.

    python app/server.py                            # opens the desktop window
    python app/server.py --pair 'lindef://...'      # pair with an agent from the terminal
    python app/server.py --headless                 # no window; prints the local URL

The agent (agent.py) runs on the server being defended. This app pairs with
it once, using the code the agent prints, keeps its device token in a private
config file, and relays the window's requests to the agent over pinned HTTPS.
The relay exists only because a web view cannot pin certificates itself.
Phones connect to the agent directly, not through this app.
Full API contract: docs/desktop_app_spec.md.
"""

import argparse
import hmac
import json
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import secure

INDEX_HTML = Path(__file__).resolve().parent / "web" / "index.html"
ICON_PNG = Path(__file__).resolve().parent / "web" / "icon.png"
DEFAULT_DATA_DIR = "~/.lindef/desktop"
LOCAL_TOKEN = secrets.token_urlsafe(24)  # per launch; guards the relay from other local programs and websites
AGENT_PATH = re.compile(r"^[a-z0-9/._-]+$")

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "UNKNOWN": 3, "CRITICAL": 4}
DEFAULT_PREFERENCES = {"system_notifications": True, "notify_min_severity": "HIGH"}
NOTIFY_POLL_SECONDS = 5
QUIET_SECONDS = 60   # at most one desktop notification a minute...
URGENT_SECONDS = 15  # ...except critical alerts and errors, which may come sooner


def show_system_notification(title: str, body: str):
    """Pop a desktop notification. Text goes in as arguments, never as script code."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["osascript", "-e", "on run argv",
                            "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                            "-e", "end run", title, body], capture_output=True, timeout=5)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", "--app-name=LINDEF", title, body], capture_output=True, timeout=5)
        # ponytail: Windows shows alerts in the app window only; add a toast library if that matters
    except (OSError, subprocess.SubprocessError):
        pass  # a missing notifier must never take the app down


class LinkError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class AgentLink:
    """This desktop's pairing with one agent, saved in config.json."""

    def __init__(self, data_dir):
        self.dir = secure.private_dir(data_dir)
        self.config_path = self.dir / "config.json"
        self.lock = threading.Lock()
        config = secure.read_json(self.config_path, {})
        self.agent = config.get("agent")
        self.preferences = {**DEFAULT_PREFERENCES, **config.get("preferences", {})}

    def save(self):
        """Write the pairing and preferences. Call while holding self.lock."""
        secure.write_json(self.config_path, {"agent": self.agent, "preferences": self.preferences})

    def set_preferences(self, changes: dict) -> dict:
        clean = {}
        for key, value in changes.items():
            if key == "system_notifications":
                clean[key] = bool(value)
            elif key == "notify_min_severity" and value in SEVERITY_RANK:
                clean[key] = value
            else:
                raise LinkError(400, f"Unknown or invalid preference: {key}")
        with self.lock:
            self.preferences.update(clean)
            self.save()
        return dict(self.preferences)

    def request(self, method: str, path: str, body: bytes | None = None, agent=None):
        """Send one request to the agent. Returns (status, body, headers)."""
        agent = agent or self.agent
        if not agent:
            raise LinkError(503, "Not paired with a LINDEF server yet. Paste the pairing code the agent printed.")
        headers = {"Content-Type": "application/json"}
        if "token" in agent:
            headers["Authorization"] = f"Bearer {agent['token']}"
        try:
            status, data, response_headers = secure.pinned_request(
                agent["host"], agent["port"], agent["fp"], method, path, body, headers)
        except secure.CertificateMismatch as exc:
            raise LinkError(502, f"{exc} If the agent was reset, pair again; otherwise someone may be "
                                 f"intercepting the connection.")
        except OSError as exc:
            raise LinkError(502, f"Can't reach the LINDEF server at {agent['host']}:{agent['port']} ({exc}). "
                                 f"Check that the agent is running and this computer can reach it.")
        if status == 401 and "token" in agent:
            raise LinkError(502, "The LINDEF server no longer recognizes this desktop. Pair again.")
        return status, data, response_headers

    def pair(self, code: str, name: str) -> dict:
        try:
            info = secure.parse_pairing_code(code)
        except ValueError as exc:
            raise LinkError(400, str(exc))
        if "pair" not in info:
            raise LinkError(400, "That code has no pairing secret. Copy the whole code the agent printed.")
        target = {"host": info["host"], "port": info["port"], "fp": info["fp"]}
        body = json.dumps({"code": info["pair"], "name": name}).encode()
        status, data, _ = self.request("POST", "/v1/pair/claim", body, agent=target)
        result = json.loads(data)
        if status != 200:
            raise LinkError(status, result.get("error", "Pairing failed."))
        with self.lock:
            self.agent = {**target, "token": result["token"], "device_id": result["device_id"],
                          "role": result["role"], "name": name}
            self.save()
        return self.status()

    def forget(self):
        """Unpair: remove this desktop from the agent (if reachable) and from the config."""
        if self.agent:
            try:
                self.request("DELETE", f"/v1/devices/{self.agent['device_id']}")
            except LinkError:
                pass  # offline agent: forget locally anyway; it can be revoked from another desktop
        with self.lock:
            self.agent = None
            self.save()

    def status(self) -> dict:
        if not self.agent:
            return {"paired": False}
        status = {"paired": True, "host": self.agent["host"], "port": self.agent["port"],
                  "device_id": self.agent["device_id"], "role": self.agent["role"], "name": self.agent["name"]}
        try:
            _, data, _ = self.request("GET", "/v1/health")
            status.update(reachable=True, health=json.loads(data))
        except LinkError as exc:
            status.update(reachable=False, error=str(exc))
        return status


def watch_notifications(link: AgentLink):
    """Turn new agent notifications into desktop notifications without spam: one
    popup per cooldown, and anything that arrives in between is rolled into the
    next one as a summary ("6 new alerts. Latest: ...")."""
    last_id, last_agent = None, None
    pending, latest, last_shown = 0, None, 0.0
    while True:
        time.sleep(NOTIFY_POLL_SECONDS)
        if not link.agent:
            continue
        try:
            if link.agent is not last_agent or last_id is None:
                _, data, _ = link.request("GET", "/v1/notifications?after=0&limit=1")
                last_id, last_agent = json.loads(data)["last_id"], link.agent  # start from now, skip backlog
                continue
            status, data, _ = link.request("GET", f"/v1/notifications?after={last_id}&limit=50")
            if status != 200:
                continue
            feed = json.loads(data)
            if feed["last_id"] < last_id:   # agent restarted: its IDs began again
                last_id = feed["last_id"]
                continue
            notes = feed["notifications"]
            if notes:
                last_id = notes[-1]["id"]
            prefs = dict(link.preferences)
            if not prefs["system_notifications"]:
                pending = 0
                continue
            minimum = SEVERITY_RANK[prefs["notify_min_severity"]]
            wanted = [n for n in notes
                      if n["kind"] == "error" or SEVERITY_RANK.get(n["severity"], 3) >= minimum]
            pending += len(wanted)
            latest = wanted[-1] if wanted else latest
            urgent = any(n["kind"] == "error" or n["severity"] == "CRITICAL" for n in wanted)
            if not pending or time.time() - last_shown < (URGENT_SECONDS if urgent else QUIET_SECONDS):
                continue  # held back; counted into the next summary
            if pending == 1:
                show_system_notification(f"LINDEF: {latest['title']}", latest["body"])
            else:
                show_system_notification(f"LINDEF: {pending} new alerts", f"Latest: {latest['title']}")
            pending, last_shown = 0, time.time()
        except (LinkError, ValueError, KeyError):
            continue  # agent offline or mid-restart: try again next poll


def make_handler(link: AgentLink):

    class Handler(BaseHTTPRequestHandler):
        server_version = "LINDEF-desktop"

        def log_message(self, *args):
            pass

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

        def authorized(self) -> bool:
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth.encode(), f"Bearer {LOCAL_TOKEN}".encode()):
                self.send_json(401, {"error": "Missing or wrong local token. Reopen the LINDEF window."})
                return False
            return True

        def body(self) -> bytes:
            return self.raw_body

        def do_GET(self):
            self.route("GET")

        def do_POST(self):
            self.route("POST")

        def do_DELETE(self):
            self.route("DELETE")

        def route(self, method: str):
            parts = urlparse(self.path)
            # Read the body before any reply, even a refusal (see agent.py).
            try:
                length = max(0, int(self.headers.get("Content-Length") or 0))
            except ValueError:
                return self.send_json(400, {"error": "Bad Content-Length."})
            if length > 64_000:
                self.close_connection = True
                return self.send_json(413, {"error": "Request body too large."})
            self.raw_body = self.rfile.read(length)
            if method == "GET" and parts.path in ("/", "/index.html"):
                return self.send(200, INDEX_HTML.read_bytes(), "text/html; charset=utf-8")
            if method == "GET" and parts.path == "/icon.png":
                return self.send(200, ICON_PNG.read_bytes(), "image/png")
            if not parts.path.startswith("/api/"):
                return self.send_json(404, {"error": "Not found."})
            if not self.authorized():
                return

            try:
                if parts.path == "/api/connection":
                    if method == "GET":
                        return self.send_json(200, link.status())
                    if method == "POST":
                        data = json.loads(self.body() or b"{}")
                        name = str(data.get("name") or f"{socket.gethostname()} desktop")[:80]
                        return self.send_json(200, link.pair(data.get("code", ""), name))
                    if method == "DELETE":
                        link.forget()
                        return self.send_json(200, link.status())

                if parts.path == "/api/preferences":
                    if method == "POST":
                        return self.send_json(200, link.set_preferences(json.loads(self.body() or b"{}")))
                    return self.send_json(200, dict(link.preferences))

                # Everything else goes to the agent: /api/state -> /v1/state, and so on.
                rest = parts.path[len("/api/"):]
                if not AGENT_PATH.match(rest) or ".." in rest:
                    return self.send_json(404, {"error": "Not found."})
                agent_path = f"/v1/{rest}" + (f"?{parts.query}" if parts.query else "")
                status, data, headers = link.request(method, agent_path, self.body() if method == "POST" else None)
                passthrough = {k: v for k, v in headers.items() if k.lower() == "content-disposition"}
                return self.send(status, data, headers.get("Content-Type", "application/json"), passthrough)

            except LinkError as exc:
                return self.send_json(exc.status, {"error": str(exc)})
            except ValueError:
                return self.send_json(400, {"error": "Request body must be JSON."})

    return Handler


def main():
    parser = argparse.ArgumentParser(description="LINDEF desktop app")
    parser.add_argument("--port", type=int, default=8765, help="local port for the window (loopback only)")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    parser.add_argument("--pair", metavar="CODE", help="pair with an agent using the code it printed")
    parser.add_argument("--headless", action="store_true", help="run without opening a window")
    args = parser.parse_args()

    link = AgentLink(args.data_dir)
    if args.pair:
        try:
            status = link.pair(args.pair, f"{socket.gethostname()} desktop")
        except LinkError as exc:
            sys.exit(f"Pairing failed: {exc}")
        print(f"Paired with the LINDEF server at {status['host']}:{status['port']} as '{status['name']}'.")

    try:
        # Loopback only: phones talk to the agent directly, never to this app.
        httpd = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(link))
    except OSError as exc:
        sys.exit(f"Could not open port {args.port} ({exc}). Try: python app/server.py --port {args.port + 1}")
    url = f"http://127.0.0.1:{args.port}/#t={LOCAL_TOKEN}"
    threading.Thread(target=watch_notifications, args=(link,), daemon=True).start()

    if not link.agent:
        print("Not paired with a LINDEF server yet. Start agent.py on the server, then pair with:")
        print("  python app/server.py --pair 'lindef://...'")

    try:
        import webview
    except ImportError:
        webview = None

    if args.headless or webview is None:
        print(f"Desktop: {url}")
        if webview is None and not args.headless:
            import webbrowser
            webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nLINDEF stopped.")
        return

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    webview.settings["ALLOW_DOWNLOADS"] = True  # lets "Download Detection Log" save the CSV
    webview.create_window("LINDEF", url, width=1320, height=880, min_size=(960, 640))
    webview.start()  # blocks until the window closes; daemon threads exit with it


if __name__ == "__main__":
    main()
