"""
Backend test for the agent, desktop app, and phone links:  python app/test_backend.py

Builds tiny stand-in models in a temp folder (the real ones are not in the
repo), runs a real agent over TLS plus the desktop relay, and plays the phone
app by calling the agent directly. Checks pairing, certificate pinning, roles,
detection in simulation and live mode, simulated containment, notifications,
device revocation, and Clear Logs.
"""

import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

import agent
import engine
import secure
import server

tmp = Path(tempfile.mkdtemp())
engine.BINARY_MODEL_PATH = tmp / "binary_model.pkl"
engine.MULTI_MODEL_PATH = tmp / "class_model.pkl"
engine.SCALER_PATH = tmp / "scaler.pkl"
engine.FEATURE_COLUMNS_PATH = tmp / "feature_columns.pkl"
engine.FEATURE_MEDIANS_PATH = tmp / "feature_medians.npy"
engine.REQUIRED_MODEL_FILES = [engine.BINARY_MODEL_PATH, engine.MULTI_MODEL_PATH,
                               engine.SCALER_PATH, engine.FEATURE_COLUMNS_PATH]
engine.LOG_FILE = tmp / "attack_log.csv"
engine.LIVE_PCAP_DIR = tmp / "live_pcaps"
engine.LIVE_CSV_DIR = tmp / "live_csvs"
engine.KEEP_CAPTURES = 2

sim_csv = tmp / "simulation_test.csv"
sources = {"simulation_csv": str(sim_csv), "tshark_path": "tshark", "interface_id": "1",
           "cicflowmeter_command": "true"}


def expect_error(error_type, fn, *args):
    try:
        fn(*args)
    except error_type:
        return
    raise AssertionError(f"{fn.__name__} should raise {error_type.__name__}")


# Without model files the agent still starts, but detection refuses to run.
assert agent.Monitor(sources).missing_models
expect_error(ValueError, agent.Monitor(sources).start)

cols = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "packet_rate", "x"]
rng = np.random.default_rng(0)
X = rng.random((200, len(cols)))
scaler = StandardScaler().fit(X)
joblib.dump(scaler, engine.SCALER_PATH)
joblib.dump(DecisionTreeClassifier().fit(scaler.transform(X), (X[:, 4] > 0.5).astype(int)), engine.BINARY_MODEL_PATH)
joblib.dump(DecisionTreeClassifier().fit(scaler.transform(X), np.where(X[:, 0] > 0.5, "neptune", "httptunnel")),
            engine.MULTI_MODEL_PATH)
joblib.dump(cols, engine.FEATURE_COLUMNS_PATH)

# Simulation CSV shaped like a CICFlowMeter export: endpoint and label columns, packet_rate missing.
sim = pd.DataFrame(X, columns=cols).drop(columns=["packet_rate"])
sim["Src IP"] = [f"10.0.0.{i % 250}" for i in range(len(sim))]
sim["Src Port"] = 40000.0
sim["Dst IP"] = "10.0.0.254"
sim["Dst Port"] = 443
sim["Label"] = "x"
sim.to_csv(sim_csv, index=False)

# Simulation rows without addresses get stable made-up ones: attacks from a few
# recurring attackers, benign traffic from many clients, all in reserved ranges.
fake = [{"Status": "ATTACK"}, {"Status": "BENIGN"}, {"Status": "ATTACK"}]
agent.add_simulated_addresses(fake, [7, 8, 7])
assert fake[0]["Source IP"] == fake[2]["Source IP"] and fake[0]["Source IP"] in agent.SIM_ATTACKERS
assert fake[1]["Source IP"].startswith(("198.18.", "198.19.")) and fake[1]["Destination IP"] in agent.SIM_HOSTS
assert agent.has_address_columns(sim) and not agent.has_address_columns(pd.DataFrame({"x": [1]}))

# ----- start the agent (TLS) and the desktop relay ----------------------------

agent_dir = secure.private_dir(tmp / "agent")
cert_path, key_path, fingerprint = secure.load_or_create_identity(agent_dir)
assert secure.load_or_create_identity(agent_dir)[2] == fingerprint  # identity persists across restarts
monitor = agent.Monitor(sources)
devices = agent.Devices(agent_dir / "devices.json")
agent_port = {}
agent_httpd = secure.TLSServer(("127.0.0.1", 0), agent.make_handler(
    monitor, devices, lambda code: secure.make_pairing_code("127.0.0.1", agent_port["p"], fingerprint, pair=code)),
    cert_path, key_path)
agent_port["p"] = agent_httpd.server_address[1]
threading.Thread(target=agent_httpd.serve_forever, daemon=True).start()
threading.Thread(target=monitor.loop, daemon=True).start()

link = server.AgentLink(tmp / "desktop")
desktop_httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(link))
desktop_base = f"http://127.0.0.1:{desktop_httpd.server_address[1]}"
threading.Thread(target=desktop_httpd.serve_forever, daemon=True).start()


def desktop(path, body=None, method=None, token=server.LOCAL_TOKEN):
    """Call the desktop relay the way the desktop window does."""
    req = urllib.request.Request(desktop_base + path, method=method or ("POST" if body is not None else "GET"),
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def phone(path, body=None, method=None, token=None, fp=fingerprint):
    """Call the agent directly, the way the native phone app does."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, data, _ = secure.pinned_request("127.0.0.1", agent_port["p"], fp,
                                            method or ("POST" if body is not None else "GET"), path,
                                            json.dumps(body).encode() if body is not None else None, headers)
    return status, data.decode()


# ----- pairing -----------------------------------------------------------------

assert desktop("/")[0] == 200
assert desktop("/api/state", token="wrong")[0] == 401
assert desktop("/api/state")[0] == 503                       # not paired yet
assert desktop("/api/connection", {"code": "https://nope"})[0] == 400

desktop_code = secure.make_pairing_code("127.0.0.1", agent_port["p"], fingerprint, pair=devices.issue_code("desktop"))
wrong_pin = desktop_code.replace(fingerprint, "0" * 64)
status, body = desktop("/api/connection", {"code": wrong_pin})
assert status == 502 and "different certificate" in body     # pinning refuses an impostor
status, body = desktop("/api/connection", {"code": desktop_code})
assert status == 200 and json.loads(body)["role"] == "desktop" and json.loads(body)["reachable"], body
assert desktop("/api/connection", {"code": desktop_code})[0] == 403  # codes work once

# Desktop notification watcher, with the system popup swapped for a recorder.
popups = []
server.show_system_notification = lambda title, body: popups.append(f"{title} {body}")
server.NOTIFY_POLL_SECONDS = 0.2
server.URGENT_SECONDS = 1.0  # short cooldowns so the test sees both the summary and the error
server.QUIET_SECONDS = 1.0
threading.Thread(target=server.watch_notifications, args=(link,), daemon=True).start()
assert json.loads(desktop("/api/preferences")[1]) == server.DEFAULT_PREFERENCES
assert desktop("/api/preferences", {"notify_min_severity": "LOUD"})[0] == 400
assert json.loads(desktop("/api/preferences", {"notify_min_severity": "LOW"})[1])["notify_min_severity"] == "LOW"
assert json.loads((tmp / "desktop" / "config.json").read_text())["preferences"]["notify_min_severity"] == "LOW"
time.sleep(0.5)  # let the watcher take its starting point
assert json.loads((tmp / "desktop" / "config.json").read_text())["agent"]["token"]
assert "token" not in (agent_dir / "devices.json").read_text().replace("token_hash", "")  # agent stores hashes only

status, body = desktop("/api/pair", {"role": "phone"})
assert status == 200 and json.loads(body)["qr"].startswith("data:image/svg+xml")
phone_info = secure.parse_pairing_code(json.loads(body)["code"])
assert phone_info["fp"] == fingerprint

expect_error(secure.CertificateMismatch, phone, "/v1/pair/claim", {"code": phone_info["pair"]}, None, None, "f" * 64)
status, body = phone("/v1/pair/claim", {"code": phone_info["pair"], "name": "Test phone"})
assert status == 200, body
phone_token = json.loads(body)["token"]
assert json.loads(body)["role"] == "phone"

stale = devices.issue_code("phone")
devices.codes[stale]["expires"] = 0
assert phone("/v1/pair/claim", {"code": stale})[0] == 403      # expired codes are refused

# ----- roles ---------------------------------------------------------------------

assert phone("/v1/state")[0] == 401
assert phone("/v1/state", token="not-a-token")[0] == 401
assert phone("/v1/state", token=phone_token)[0] == 200
assert phone("/v1/settings", {"mode": "live"}, token=phone_token)[0] == 403
assert phone("/v1/pair", {"role": "phone"}, token=phone_token)[0] == 403
assert phone("/v1/devices", token=phone_token)[0] == 403
assert phone("/v1/settings", {"refresh_seconds": 0.5}, token=phone_token)[0] == 200
assert desktop("/api/settings", {"cicflowmeter_command": "rm -rf ~"})[0] == 403  # nobody, not even the desktop
assert desktop("/api/settings", {"bogus": 1})[0] == 400
assert desktop("/api/settings", {"refresh_seconds": "fast"})[0] == 400
status, body = desktop("/api/settings", {"rows_per_step": 999, "mode": "simulation"})
assert status == 200 and json.loads(body)["settings"]["rows_per_step"] == 100  # clamped

# ----- detection (simulation) -------------------------------------------------------

assert phone("/v1/start", {}, token=phone_token)[0] == 200
for _ in range(80):
    state = json.loads(desktop("/api/state")[1])
    if state["metrics"]["total"] >= 200:
        break
    time.sleep(0.1)
assert state["metrics"]["total"] >= 200 and not state["error"], (state["metrics"], state["error"])
assert state["metrics"]["attacks"] + state["metrics"]["benign"] == state["metrics"]["total"]
assert len(state["recent"]) == agent.RECENT_ROWS
assert {r["Status"] for r in state["recent"]} <= {"ATTACK", "BENIGN"}
assert set(state["charts"]) == {"status", "severity", "attacks", "responses"}
row = state["recent"][-1]
assert row["Source IP"].startswith("10.0.0.") and row["Source Port"] == "40000" and row["Destination Port"] == "443"

first = json.loads(phone("/v1/detections?after=0&limit=10", token=phone_token)[1])
assert [r["ID"] for r in first["records"]] == list(range(1, 11))
assert desktop("/api/detections?after=abc")[0] == 400
assert desktop("/api/stop", {})[0] == 200
time.sleep(0.6)  # let an in-flight cycle finish
last_id = json.loads(desktop("/api/state")[1])["last_id"]
assert json.loads(phone(f"/v1/detections?after={last_id}", token=phone_token)[1])["records"] == []

status, body = desktop("/api/log.csv")
assert status == 200 and body.startswith("ID,Time,Status,Attack") and ",Contained" in body.splitlines()[0]
assert json.loads(desktop("/api/model")[1])["feature_count"] == len(cols)
assert desktop("/api/../secret")[0] == 404

# ----- simulated containment and notifications ---------------------------------------

state = json.loads(desktop("/api/state")[1])
box = state["containment"]
assert box["enforcement"] == "simulated" and box["active"], box
assert state["metrics"]["contained"] > 0 and box["flows_stopped"] > 0
assert {r["Contained"] for r in state["recent"]} - {None} <= {"BLOCKED", "THROTTLED", "ISOLATED"}
isolate = next(a for a in box["active"] if a["action"] == "ISOLATE_HOST")
assert isolate["target"] == "10.0.0.254" and isolate["expires"] > time.time() and isolate["simulated"]
block = next(a for a in box["active"] if a["action"] == "BLOCK_IP")
assert block["target"].startswith("10.0.0.") and block["expires"] > time.time()
assert not state["simulated_addresses"]  # this CSV has real address columns

notes = json.loads(phone("/v1/notifications?after=0", token=phone_token)[1])
assert notes["last_id"] == state["notifications_last_id"] > 0
assert any(n["kind"] == "containment" and n["title"].endswith("(simulated)") for n in notes["notifications"])
assert phone("/v1/notifications?after=abc", token=phone_token)[0] == 400

assert phone(f"/v1/containment/{block['id']}/lift", {}, token=phone_token)[0] == 403
status, body = desktop(f"/api/containment/{block['id']}/lift", {})
assert status == 200 and block["id"] not in [a["id"] for a in json.loads(body)["active"]]
lifted = json.loads(body)["lifted"]
assert lifted["ended"] == "lifted" and lifted["ended_by"].endswith("desktop")
assert desktop(f"/api/containment/{block['id']}/lift", {})[0] == 404
assert desktop("/api/containment/abc/lift", {})[0] == 404

# A broken source raises one error notification, not one per cycle.
monitor.settings["simulation_csv"] = str(tmp / "missing.csv")
assert desktop("/api/start", {})[0] == 200
time.sleep(1.5)
desktop("/api/stop", {})
errors = [n for n in json.loads(desktop("/api/notifications?after=0&limit=200")[1])["notifications"]
          if n["kind"] == "error"]
assert len(errors) == 1 and errors[0]["title"] == "Detection stopped working", errors
assert "not found" in json.loads(desktop("/api/state")[1])["error"]
monitor.settings["simulation_csv"] = str(sim_csv)
time.sleep(0.6)
assert any("(simulated)" in t for t in popups) and any("Detection stopped working" in t for t in popups), popups
assert len(popups) <= 8, popups  # hundreds of alerts became a handful of summaries

# ----- devices --------------------------------------------------------------------

listing = json.loads(desktop("/api/devices")[1])["devices"]
assert sorted(d["role"] for d in listing) == ["desktop", "phone"]
phone_id = next(d["device_id"] for d in listing if d["role"] == "phone")
assert next(d for d in listing if d["role"] == "phone")["online"]
assert desktop(f"/api/devices/{phone_id}", method="DELETE")[0] == 200
assert phone("/v1/state", token=phone_token)[0] == 401          # unlinked phone is locked out
assert desktop("/api/devices/nope", method="DELETE")[0] == 404

# ----- Clear Logs ---------------------------------------------------------------------

state = json.loads(desktop("/api/clear", {})[1])
assert state["metrics"]["total"] == 0 and not engine.LOG_FILE.exists()
assert state["containment"]["active"] == []                      # Clear Logs also lifts containment
assert all(a["ended"] for a in state["containment"]["history"])
assert state["last_id"] == last_id                                # IDs never repeat after a clear
monitor.append([{"Status": "ATTACK"}], monitor.epoch - 1)          # batch that was in flight during Clear
assert monitor.logs == []

# ----- live mode with stand-in TShark and CICFlowMeter ------------------------------

fake_tshark = tmp / "tshark"
fake_tshark.write_text(f"#!{sys.executable}\n"
                       "import sys; open(sys.argv[sys.argv.index('-w') + 1], 'wb').write(b'pcap')\n")
fake_tshark.chmod(0o755)
fake_cic = tmp / "cic.py"
fake_cic.write_text("import shutil, sys\n"
                    f"shutil.copy({str(sim_csv)!r}, sys.argv[2] + '/flows.csv')\n")  # reused filename
monitor.settings.update(tshark_path=str(fake_tshark),  # what --tshark / --cicflowmeter set on the server
                        cicflowmeter_command=f'"{sys.executable}" "{fake_cic}" "{{input}}" "{{output}}"')
assert desktop("/api/settings", {"mode": "live", "capture_duration": 2, "refresh_seconds": 0.5})[0] == 200
assert desktop("/api/start", {})[0] == 200
for _ in range(100):
    state = json.loads(desktop("/api/state")[1])
    if state["metrics"]["total"] >= 3 * len(sim):
        break
    time.sleep(0.1)
desktop("/api/stop", {})
time.sleep(0.6)
assert state["metrics"]["total"] >= 3 * len(sim) and not state["error"], (state["metrics"], state["error"])
assert state["metrics"]["total"] % len(sim) == 0                   # whole captures only, no re-read duplicates
assert not list(engine.LIVE_CSV_DIR.glob("*.csv"))                # derived CSVs cleaned up
assert 1 <= len(list(engine.LIVE_PCAP_DIR.glob("*.pcap"))) <= engine.KEEP_CAPTURES  # old pcaps pruned

# ----- unpair the desktop -------------------------------------------------------------

status, body = desktop("/api/connection", method="DELETE")
assert status == 200 and json.loads(body) == {"paired": False}
assert devices.listing() == []

print("ok: agent, desktop, and phone backend test passed")
