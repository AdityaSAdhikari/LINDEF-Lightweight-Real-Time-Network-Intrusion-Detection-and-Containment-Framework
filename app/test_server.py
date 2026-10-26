"""
Smoke test for the LINDEF backend:  python app/test_server.py

Builds tiny stand-in models in a temp folder (the real ones are not in the
repo), starts the API on a free port, and checks pairing, detection, the
desktop-only settings rule, and the CSV log.
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

import engine
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

# Without model files the app still starts, but detection refuses to run.
assert server.Monitor().missing_models
try:
    server.Monitor().start()
    raise AssertionError("start() should fail without models")
except ValueError:
    pass

cols = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "packet_rate", "x"]
rng = np.random.default_rng(0)
X = rng.random((200, len(cols)))
scaler = StandardScaler().fit(X)
joblib.dump(scaler, engine.SCALER_PATH)
joblib.dump(DecisionTreeClassifier().fit(scaler.transform(X), (X[:, 4] > 0.5).astype(int)), engine.BINARY_MODEL_PATH)
joblib.dump(DecisionTreeClassifier().fit(scaler.transform(X), np.where(X[:, 0] > 0.5, "neptune", "httptunnel")),
            engine.MULTI_MODEL_PATH)
joblib.dump(cols, engine.FEATURE_COLUMNS_PATH)

# Simulation CSV shaped like real exports: extra ID/label columns, packet_rate missing.
sim_csv = tmp / "simulation_test.csv"
sim = pd.DataFrame(X, columns=cols).drop(columns=["packet_rate"])
sim["Flow ID"] = "10.0.0.1-10.0.0.2"
sim["Label"] = "x"
sim.to_csv(sim_csv, index=False)

monitor = server.Monitor()
assert not monitor.missing_models
handler, _ = server.make_handler(monitor, 0)
httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
base = f"http://127.0.0.1:{httpd.server_address[1]}"
threading.Thread(target=httpd.serve_forever, daemon=True).start()
threading.Thread(target=monitor.loop, daemon=True).start()


def call(path, body=None, token=server.TOKEN):
    req = urllib.request.Request(base + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Lindef-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


assert call("/")[0] == 200
assert call("/api/state", token="wrong")[0] == 401
assert call("/api/settings", {"bogus": 1})[0] == 400
assert call("/api/settings", {"refresh_seconds": "fast"})[0] == 400

status, body = call("/api/settings", {"simulation_csv": str(sim_csv), "refresh_seconds": 0.5, "rows_per_step": 999})
assert status == 200 and json.loads(body)["settings"]["rows_per_step"] == 100  # clamped

try:
    monitor.update_settings({"cicflowmeter_command": "rm -rf ~"}, from_desktop=False)
    raise AssertionError("phones must not change shell commands")
except PermissionError:
    pass
monitor.update_settings({"refresh_seconds": 1}, from_desktop=False)  # harmless settings are fine

assert call("/api/start", {})[0] == 200
for _ in range(50):
    state = json.loads(call("/api/state")[1])
    if state["metrics"]["total"] >= 200:
        break
    time.sleep(0.1)
assert state["metrics"]["total"] >= 200, state
assert state["metrics"]["attacks"] + state["metrics"]["benign"] == state["metrics"]["total"]
assert len(state["recent"]) == server.RECENT_ROWS
assert {r["Status"] for r in state["recent"]} <= {"ATTACK", "BENIGN"}
assert set(state["charts"]) == {"status", "severity", "attacks", "responses"}
assert "devices" in state and not state["error"]

assert call("/api/stop", {})[0] == 200
assert call("/api/log.csv")[1].startswith("Time,Status,Attack")
assert engine.LOG_FILE.exists()
assert "<svg" in json.loads(call("/api/pair")[1])["svg"]
assert json.loads(call("/api/model")[1])["feature_count"] == len(cols)

state = json.loads(call("/api/clear", {})[1])
assert state["metrics"]["total"] == 0 and not engine.LOG_FILE.exists()

# A batch that was already in flight when Clear Logs ran must not reappear.
stale_epoch = monitor.epoch - 1
monitor.append([{"Status": "ATTACK"}], stale_epoch)
assert monitor.logs == []

# Live mode, with stand-in TShark and CICFlowMeter scripts.
server.MAX_LOGS = 10_000  # three captures of 200 flows would overflow the normal 500 cap
fake_tshark = tmp / "tshark"
fake_tshark.write_text(f"#!{sys.executable}\n"
                       "import sys; open(sys.argv[sys.argv.index('-w') + 1], 'wb').write(b'pcap')\n")
fake_tshark.chmod(0o755)
fake_cic = tmp / "cic.py"
fake_cic.write_text("import shutil, sys\n"
                    f"shutil.copy({str(sim_csv)!r}, sys.argv[2] + '/flows.csv')\n")  # reused filename
monitor.update_settings({"mode": "live", "tshark_path": str(fake_tshark), "capture_duration": 2,
                         "refresh_seconds": 0.5,
                         "cicflowmeter_command": f'"{sys.executable}" "{fake_cic}" "{{input}}" "{{output}}"'},
                        from_desktop=True)
assert call("/api/start", {})[0] == 200
for _ in range(100):
    state = json.loads(call("/api/state")[1])
    if state["metrics"]["total"] >= 3 * len(sim):  # three capture cycles
        break
    time.sleep(0.1)
call("/api/stop", {})
time.sleep(0.6)  # let an in-flight cycle finish
assert state["metrics"]["total"] >= 3 * len(sim) and not state["error"], (state["metrics"], state["error"])
assert state["metrics"]["total"] % len(sim) == 0  # whole captures only, no re-read duplicates
assert not list(engine.LIVE_CSV_DIR.glob("*.csv"))  # derived CSVs cleaned up
assert 1 <= len(list(engine.LIVE_PCAP_DIR.glob("*.pcap"))) <= engine.KEEP_CAPTURES  # old pcaps pruned

print("ok: backend smoke test passed")
