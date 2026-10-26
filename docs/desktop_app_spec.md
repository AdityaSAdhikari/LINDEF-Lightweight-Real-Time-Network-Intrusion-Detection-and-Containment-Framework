# LINDEF Desktop App — Specification

LINDEF runs as a desktop application on the machine being protected. A phone on
the same network can pair with it to watch detections live and start or stop
monitoring. It will replace the earlier Streamlit dashboard, keeping every one of its
features (see [Feature parity](#feature-parity)). Until the new frontend is
built, `app/dashboard.py` stays in place and `app/web/index.html` is a placeholder.

## Architecture

```text
 ┌──────────────────────── Desktop machine ─────────────────────────┐
 │                                                                   │
 │  app/server.py                                                    │
 │  ├── Monitor thread ── engine.py ── models/*.pkl                  │
 │  │     every refresh: read flows -> classify -> append to log     │
 │  │     source: simulation CSV  or  TShark -> CICFlowMeter          │
 │  │                                                                │
 │  ├── HTTP API on 0.0.0.0:8765  (stdlib ThreadingHTTPServer)       │
 │  │                                                                │
 │  └── Native window (pywebview) -> http://127.0.0.1:8765/#t=TOKEN  │
 │                                                                   │
 └───────────────────────────────▲───────────────────────────────────┘
                                 │  same Wi-Fi / LAN
                       Phone browser -> http://<lan-ip>:8765/#t=TOKEN
                       (opened by scanning the pairing QR code)
```

| File | Role |
|---|---|
| `app/engine.py` | Detection engine: model loading, feature alignment, TShark/CICFlowMeter helpers, classification, severity and response mapping. No UI code. |
| `app/server.py` | HTTP API, detection loop, pairing, and the desktop window launcher. |
| `app/web/index.html` | The single frontend, served to both the desktop window and phones. |
| `app/test_server.py` | Backend smoke test with stand-in models. |

One frontend serves both screens. The page reads `desktop` from `/api/state`
and shows desktop-only controls (traffic source, pairing) only on the desktop.

## Running

```bash
pip install -r requirements.txt
python app/server.py               # desktop window
python app/server.py --headless    # server only; prints desktop + phone links and a terminal QR code
python app/server.py --port 8766   # if 8765 is taken
python app/test_server.py          # backend smoke test
```

If pywebview is not installed, the app opens the desktop UI in the default browser.
If model files are missing, the app still opens, lists the missing files, and keeps
detection disabled.

## Pairing and security model

LINDEF executes user-configured shell commands (TShark, CICFlowMeter), so the
network-facing API is treated as a trust boundary.

1. **Pairing token.** A random token (`secrets.token_urlsafe(24)`) is created at each
   launch. The desktop window and the phone QR code both carry it in the URL
   *fragment* (`#t=...`), so it is never sent in a request line or stored in server
   logs. The page moves it into `localStorage` and sends it on every API call as the
   `X-Lindef-Token` header. Tokens are compared with `hmac.compare_digest`.
2. **Every `/api/*` route requires the token.** Without it: `401`. The HTML page
   itself holds no secrets and is served without a token.
3. **Desktop-only actions.** Requests from loopback (`127.0.0.1`/`::1`) count as the
   desktop. Only the desktop can:
   - view the pairing QR code and link (`GET /api/pair`);
   - change traffic-source settings: `mode`, `simulation_csv`, `tshark_path`,
     `interface_id`, `cicflowmeter_command` (these feed shell commands and file paths).

   Phones get `403` for these.
4. **Cross-site requests.** A token in a custom header forces a CORS preflight,
   which the server never approves, so other websites open on the desktop cannot
   drive the API.
5. **Connected devices.** The desktop sees each paired phone (IP, user agent, last
   seen) for 30 seconds after its latest request.
6. **Re-pairing.** Restarting the app issues a new token, which disconnects every
   phone.

Known limits: traffic is plain HTTP on the local network, so someone sniffing the
same Wi-Fi could read the token. Do not use the phone link on untrusted networks.

## API

All responses are JSON unless noted. All `/api/*` routes need `X-Lindef-Token`.
Errors return `{"error": "message"}` with status `400` (bad input), `401` (not
paired), `403` (desktop only), or `404`.

| Method | Path | Who | Body | Returns |
|---|---|---|---|---|
| GET | `/` | anyone | — | the frontend HTML |
| GET | `/api/state` | paired | — | [State](#state-object) |
| POST | `/api/start` | paired | — | State. `400` if models are not loaded. |
| POST | `/api/stop` | paired | — | State |
| POST | `/api/clear` | paired | — | State. Empties the session log, resets the simulation position, deletes `attack_log.csv`. |
| POST | `/api/settings` | paired (some keys desktop only) | partial [Settings](#settings) object | State |
| GET | `/api/log.csv` | paired | — | `text/csv` session log (download) |
| GET | `/api/model` | paired | — | model paths, `loaded`, `missing`, `feature_count`, `medians_loaded`, `feature_columns` |
| GET | `/api/pair` | desktop | — | `{"url": phone link, "svg": QR code SVG}` |

The frontend polls `GET /api/state` every 1.5 seconds. Polling is chosen over
WebSockets/SSE because it works on every phone browser and needs no extra server
code at this refresh rate.

### Settings

| Key | Type | Default | Limits | Desktop only |
|---|---|---|---|---|
| `mode` | `"simulation"` \| `"live"` | `"simulation"` | — | yes |
| `refresh_seconds` | number | 2.0 | 0.5 – 10 (clamped) | no |
| `rows_per_step` | integer | 10 | 1 – 100 (clamped) | no |
| `simulation_csv` | string | `results/simulation_test.csv` | ≤ 1000 chars | yes |
| `tshark_path` | string | `tshark` | ≤ 1000 chars | yes |
| `interface_id` | string | `1` | ≤ 1000 chars | yes |
| `capture_duration` | integer seconds | 5 | 2 – 20 (clamped) | no |
| `cicflowmeter_command` | string with `{input}` / `{output}` | `CICFlowMeter.bat "{input}" "{output}"` | ≤ 1000 chars | yes |

Unknown keys or non-numeric numbers return `400`.

### State object

```json
{
  "running": true,
  "error": "",
  "desktop": true,
  "settings": { "...": "see Settings" },
  "models": { "loaded": true, "missing": [] },
  "metrics": { "total": 120, "attacks": 47, "benign": 73, "latest": "ATTACK" },
  "recent": [
    { "Time": "12:01:05", "Status": "ATTACK", "Attack": "neptune",
      "Attack Probability": 0.987, "Severity": "HIGH", "Response": "BLOCK_IP" }
  ],
  "charts": {
    "status":    [["BENIGN", 73], ["ATTACK", 47]],
    "severity":  [["NONE", 73], ["HIGH", 30], ["CRITICAL", 17]],
    "attacks":   [["neptune", 30], ["httptunnel", 17]],
    "responses": [["ALLOW", 73], ["BLOCK_IP", 30], ["ISOLATE_HOST", 17]]
  },
  "devices": [ { "ip": "192.168.1.20", "agent": "Mozilla/5.0 ...", "seconds_ago": 1 } ]
}
```

- `recent` is the latest 50 records, oldest first. `Attack Probability` is `null` when the binary model has no `predict_proba`.
- Chart lists are sorted by count, highest first. `attacks` excludes `normal`.
- `devices` is only present for the desktop.
- `latest` is `"Waiting"` until the first flow is classified.

## Detection loop

- Runs on a daemon thread. Each cycle: if running, take one batch, classify it, append the records, save the session log to `attack_log.csv`, then wait `refresh_seconds`.
- **Simulation:** takes `rows_per_step` rows from the CSV, starting where the last batch ended and wrapping to the start of the file. The CSV is re-read only when the file changes.
- **Live:** captures `capture_duration` seconds with TShark, converts the capture with CICFlowMeter, and classifies every resulting flow. The CICFlowMeter CSV is deleted after it is read, so the same flows are never classified twice. Only the newest 20 pcaps are kept in `live_pcaps/`, so live mode cannot fill the disk. A capture with no flows counts as a quiet cycle, not an error.
- The binary model scores the whole batch in one call. The attack classifier then runs once on all flagged flows together, rather than once per flow.
- The session log keeps the latest 500 records.
- Any error (missing CSV, TShark or CICFlowMeter failure, feature mismatch) is shown as `error` in the state, and the loop retries on the next cycle. A successful cycle clears the error.
- Start, and any settings change, wake the loop immediately instead of waiting for the next cycle.
- Clear Logs discards any batch that was already being processed, so cleared detections never reappear.
- Settings and the log are guarded by one lock. Slow work (capture, conversion, classification) runs outside it, so the API stays responsive during a live capture.

## Frontend requirements

The visual language follows the LINDEF poster (`docs/LINDEF_poster.pdf`): a clean white
paper page, serif headings, thin ruled borders, research-table styling. No emojis.
An optional dark mode is toggled from the header and remembered on that device.

**Both screens**
- Header: product name, run status, theme toggle.
- Start / Stop / Clear Logs.
- Refresh speed and flows-per-refresh controls.
- Metrics: Total Flows Checked, Detected Attacks, Benign Flows, Latest Status.
- Error banner when `error` is set; models-missing notice listing the files.
- Recent Detections table (latest 50, newest at top, probability to 4 decimals, severity marked by level).
- Four distributions: Attack vs. Benign, Severity Distribution, Attack Types, Recommended Responses.
- Download Detection Log (CSV).
- Model and feature details panel, with an optional list of expected feature columns.

**Desktop only**
- Traffic source: mode switch; simulation CSV path; or TShark path, interface ID, capture duration, CICFlowMeter command.
- Phone pairing panel: QR code, link, and connected devices.

**Phone**
- A single-column layout; the detections table becomes a stacked list.
- Shows a clear "Not paired" screen if the token is missing or rejected.

## Feature parity

| Streamlit dashboard | Desktop app |
|---|---|
| Input mode radio (Simulation CSV / Live Capture) | Traffic source switch (desktop) |
| Refresh speed slider 0.5–10 s | Same, desktop and phone |
| Flows per refresh slider 1–100 | Same, desktop and phone |
| Simulation CSV path | Same (desktop) |
| TShark path, interface ID, capture duration | Same (desktop) |
| CICFlowMeter command with `{input}`/`{output}` | Same (desktop) |
| Start / Stop / Clear Logs | Same, desktop and phone |
| Four status metrics | Same |
| Error warning | Error banner |
| Missing-model error | Missing-model notice; app still opens |
| Recent Detections (last 50) | Same |
| Four bar charts | Four distributions |
| Download Detection Log | Same |
| Model and feature details expander | Same |
| `attack_log.csv` written on every update | Same |

## Out of scope / future work

- Push notifications to a locked phone (needs HTTPS or a relay such as ntfy).
- HTTPS for the phone link.
- A persistent token or multiple named phones.
- Access from outside the local network.
