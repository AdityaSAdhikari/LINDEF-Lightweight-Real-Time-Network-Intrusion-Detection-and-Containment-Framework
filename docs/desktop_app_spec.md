# LINDEF Agent, Desktop App, and Phone App: Backend Specification

LINDEF has three parts. The **agent** runs on the server being defended: it
captures traffic, classifies it, and keeps the detection log. The **desktop
app** and the **native phone app** are both clients of the agent. Each connects
to the agent directly; neither relays through the other.

```text
                  ┌────────────────────────────────────────┐
                  │  Defended server                        │
                  │  app/agent.py  (HTTPS :9443)            │
                  │   ├─ detection loop ── engine.py        │
                  │   │    simulation CSV or                │
                  │   │    TShark -> CICFlowMeter           │
                  │   ├─ paired devices (devices.json)      │
                  │   └─ certificate (cert.pem / key.pem)   │
                  └──────────▲──────────────────▲───────────┘
                 pinned HTTPS│                  │pinned HTTPS
                 role=desktop│                  │role=phone
       ┌─────────────────────┴───────┐   ┌──────┴──────────────────┐
       │ Desktop computer            │   │ Phone                    │
       │ app/server.py               │   │ native app               │
       │  window ── local relay      │   │ (talks to the agent      │
       │  (127.0.0.1 only)           │   │  directly)               │
       └─────────────────────────────┘   └──────────────────────────┘
```

| File | Role |
|---|---|
| `app/engine.py` | Detection: model loading, feature alignment, TShark/CICFlowMeter helpers, classification, severity/response mapping, flow source and destination. |
| `app/agent.py` | The agent: detection loop, device pairing and roles, HTTPS API. |
| `app/server.py` | The desktop app: native window plus a loopback-only relay that holds the desktop's device token. |
| `app/secure.py` | Certificates, pinning, pairing codes, the TLS server, and the pinned HTTPS client. |
| `app/test_backend.py` | End-to-end test of agent, desktop relay, and phone calls. |
| `app/web/index.html` | Desktop window interface (paper design, optional dark mode). |
| `ios/` | Native iPhone app (SwiftUI, iOS 17+). Open `ios/LINDEF.xcodeproj` in Xcode. |

`app/dashboard.py` (the original Streamlit dashboard) is unchanged and still
works on its own.

## Running

```bash
pip install -r requirements.txt

# On the server being defended
python app/agent.py                                       # simulation mode
python app/agent.py --tshark /usr/bin/tshark --interface eth0 \
    --cicflowmeter 'cicflowmeter -f "{input}" -c "{output}/flows.csv"'

# On the desktop
python app/server.py --pair 'lindef://...'                # first time: code printed by the agent
python app/server.py                                      # afterwards

# Tests
python app/test_backend.py
```

| Agent flag | Default | Purpose |
|---|---|---|
| `--port` | 9443 | HTTPS port |
| `--bind` | 0.0.0.0 | Listen address |
| `--advertise` | this machine's LAN IP | Host name or IP put in pairing codes (use the public name if devices reach the server through DNS or a VPN) |
| `--data-dir` | `~/.lindef/agent` | Certificate, key, and paired devices |
| `--simulation-csv` | `results/simulation_test.csv` | Simulation source |
| `--tshark` | `tshark` | TShark executable |
| `--interface` | `1` | Capture interface (`tshark -D` lists them) |
| `--cicflowmeter` | `CICFlowMeter.bat "{input}" "{output}"` | CICFlowMeter command |
| `--pair desktop\|phone` | — | Print a pairing code for that device type on start (repeatable) |
| `--reset` | — | New certificate and unpair every device |

Live capture needs permission to capture packets (for example, membership in
the `wireshark` group on Linux, or running as an administrator on Windows).

| Desktop flag | Default | Purpose |
|---|---|---|
| `--pair CODE` | — | Pair with an agent |
| `--port` | 8765 | Loopback port for the window |
| `--data-dir` | `~/.lindef/desktop` | Saved pairing (`config.json`) |
| `--headless` | — | No window; print the local URL |

## Security model

The agent controls packet capture on a production server, so every network
path is authenticated and encrypted.

1. **Encryption with pinned certificates.** On first start the agent creates an
   EC P-256 key and a self-signed certificate (`cert.pem`, `key.pem`, mode 0600).
   Every pairing code carries the certificate's SHA-256 fingerprint. Clients
   check the fingerprint **before sending anything** and refuse any other
   certificate, so an attacker on the network cannot impersonate the agent.
   There is no certificate authority. The certificate lasts ten years, because
   with pinning an expiry date adds only breakage. TLS 1.2 is the minimum.
2. **Pairing codes.** `lindef://HOST:PORT?pair=CODE&fp=FINGERPRINT`. A code is
   random (128 bits), bound to a role (`desktop` or `phone`), single use, and
   valid for 10 minutes. The agent prints a desktop code on start until a
   desktop has been paired. After that, a paired desktop creates phone codes
   (shown as a QR code). Phones cannot create codes.
3. **One token per device.** Claiming a code returns a 256-bit device token. The
   agent stores only its SHA-256 hash, so a copied `devices.json` cannot be used
   to connect. Each request sends `Authorization: Bearer TOKEN`. A lost phone is
   unlinked from the desktop without affecting other devices.
4. **Roles.**

   | Action | Desktop | Phone |
   |---|---|---|
   | View state, detections, log, model details | yes | yes |
   | Start, Stop, Clear Logs | yes | yes |
   | Change refresh speed, flows per refresh, capture duration | yes | yes |
   | Switch simulation / live mode | yes | no |
   | Create pairing codes, list and unlink devices | yes | no |
   | Change TShark, CICFlowMeter, interface, simulation CSV | no | no |

   Commands and paths that run on the defended server are set only with agent
   flags, on the server itself. A stolen device token therefore cannot run
   commands on the server.
5. **The desktop relay** listens on `127.0.0.1` only and needs a per-launch local
   token (given to the window in the URL fragment, never sent to the server in a
   request line). The token sits in a custom header, so browsers block other
   websites from calling the relay. The relay exists only because a web view
   cannot pin certificates. Its saved device token is in
   `~/.lindef/desktop/config.json` (mode 0600).
6. **Reset.** `python app/agent.py --reset` replaces the certificate and unpairs
   every device. Clients then refuse to connect (fingerprint mismatch) until they
   pair again.

## Agent API (`/v1`)

Base URL: `https://HOST:PORT`. JSON unless noted. Every route except
`POST /v1/pair/claim` needs a device token. Errors are `{"error": "message"}`
with `400` (bad input), `401` (not paired / unlinked), `403` (role not
allowed), `404`, or `413` (body over 64 KB).

| Method | Path | Role | Body | Returns |
|---|---|---|---|---|
| POST | `/v1/pair/claim` | none (the code is the credential) | `{"code", "name"}` | `{"device_id", "role", "token"}` |
| GET | `/v1/health` | any | — | `{"version", "server", "running", "models_loaded", "device_id", "device_name", "role"}` |
| GET | `/v1/state` | any | — | [State](#state) |
| GET | `/v1/detections?after=ID&limit=N` | any | — | `{"records": [Detection...], "last_id", "epoch"}`: detections with ID above `after`, oldest first, `limit` 1–500 (default 200) |
| POST | `/v1/start` | any | — | State. `400` if models are not loaded. |
| POST | `/v1/stop` | any | — | State |
| POST | `/v1/clear` | any | — | State. Empties the log and deletes `attack_log.csv`. |
| POST | `/v1/settings` | any (`mode`: desktop) | partial [Settings](#settings) | State |
| GET | `/v1/log.csv` | any | — | `text/csv` session log |
| GET | `/v1/model` | any | — | model paths, `loaded`, `missing`, `feature_count`, `medians_loaded`, `feature_columns` |
| GET | `/v1/notifications?after=ID&limit=N` | any | — | `{"notifications": [Notification...], "last_id"}`, oldest first, `limit` 1–200 (default 100) |
| GET | `/v1/containment` | any | — | [Containment](#simulated-containment) summary |
| POST | `/v1/containment/{id}/lift` | desktop | — | Containment summary plus `"lifted": action`. `404` if not active. |
| POST | `/v1/pair` | desktop | `{"role": "phone" \| "desktop"}` | `{"code": "lindef://...", "qr": QR code as a data: SVG image, "expires_in": 600}` |
| GET | `/v1/devices` | desktop | — | `{"devices": [{"device_id", "name", "role", "paired_at", "online", "last_seen_seconds", "ip"}]}` |
| DELETE | `/v1/devices/{id}` | desktop | — | updated device list |

**Polling.** Apps poll `GET /v1/state` for the dashboard (every 1–2 seconds
while visible) and `GET /v1/detections?after=<last ID seen>` to get only new
detections, for example to raise in-app alerts for new attacks. Detection IDs
increase and are never reused, even after Clear Logs. `epoch` changes when the
log is cleared, so an app knows to drop its local copy.

### Detection

```json
{ "ID": 1042, "Time": "12:01:05", "Status": "ATTACK", "Attack": "neptune",
  "Attack Probability": 0.987, "Severity": "HIGH", "Response": "BLOCK_IP",
  "Source IP": "203.0.113.7", "Source Port": "51544",
  "Destination IP": "10.0.0.5", "Destination Port": "443", "Contained": null }
```

- `Status`: `ATTACK` or `BENIGN`. `Severity`: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or `UNKNOWN`.
- `Response` (recommended containment): `ALLOW`, `BLOCK_IP`, `THROTTLE_IP`, `ISOLATE_HOST`, or `MONITOR`.
- `Attack Probability` is `null` if the binary model has no `predict_proba`.
- Source and destination come from CICFlowMeter, CIC-IDS2017, or UNSW-NB15 columns when present. They are never used as model features. In simulation mode, when the CSV has no address columns, they are simulated (see below); in live mode without them they are `null`.
- `Contained`: `BLOCKED`, `THROTTLED`, or `ISOLATED` when the simulated firewall would have stopped this flow, otherwise `null`.

### Settings

| Key | Type | Default | Limits | Changed by |
|---|---|---|---|---|
| `mode` | `"simulation"` \| `"live"` | `simulation` | — | desktop |
| `refresh_seconds` | number | 2.0 | 0.5–10, clamped | desktop, phone |
| `rows_per_step` | integer | 10 | 1–100, clamped | desktop, phone |
| `capture_duration` | integer seconds | 5 | 2–20, clamped | desktop, phone |
| `simulation_csv`, `tshark_path`, `interface_id`, `cicflowmeter_command` | string | from flags | — | agent flags only (`403` over the API) |

All settings, including the flag-only ones, are returned in State so apps can show them.

### State

```json
{
  "running": true,
  "error": "",
  "settings": { "mode": "live", "refresh_seconds": 2.0, "rows_per_step": 10, "capture_duration": 5,
                "simulation_csv": "...", "tshark_path": "tshark", "interface_id": "eth0",
                "cicflowmeter_command": "..." },
  "models": { "loaded": true, "missing": [] },
  "simulated_addresses": true,
  "last_id": 1042,
  "epoch": 0,
  "notifications_last_id": 88,
  "metrics": { "total": 120, "attacks": 47, "benign": 73, "contained": 19, "latest": "ATTACK" },
  "containment": { "enforcement": "simulated", "active": ["Action..."], "history": ["latest 50 Actions"], "flows_stopped": 19 },
  "recent": [ "latest 50 Detections, oldest first" ],
  "charts": {
    "status":    [["BENIGN", 73], ["ATTACK", 47]],
    "severity":  [["NONE", 73], ["HIGH", 30], ["CRITICAL", 17]],
    "attacks":   [["neptune", 30], ["httptunnel", 17]],
    "responses": [["ALLOW", 73], ["BLOCK_IP", 30], ["ISOLATE_HOST", 17]]
  }
}
```

`labels` maps attack and response codes to readable names for display (for example `guess_passwd` to "Password guessing", `BLOCK_IP` to "Block IP"); the API itself keeps the codes. Chart lists are sorted by count. `attacks` excludes `normal`. Metrics cover
the session log (latest 500 detections).

## Simulated containment

LINDEF acts as if it contains attacks but never changes real traffic, in
simulation and live mode alike. `enforcement` is always `"simulated"`.

- An `ATTACK` whose response is `BLOCK_IP` or `THROTTLE_IP` starts an action against its **source** address; `ISOLATE_HOST` starts one against its **destination** (the affected host).
- Durations: block 15 minutes, throttle 10 minutes, isolate 10 minutes. A repeat attack on an active target renews the timer and counts as another trigger instead of starting a new action.
- Later flows are marked `Contained`: from a blocked or throttled source, or to an isolated host. Each action counts the flows it stopped.
- The desktop can lift an action early. Clear Logs lifts all actions.
- Without a target address (live capture with no IP columns), no action starts.

```json
{ "id": 12, "action": "BLOCK_IP", "target": "203.0.113.7", "target_kind": "source",
  "attack": "neptune", "last_attack": "neptune", "severity": "HIGH", "detection_id": 1042,
  "started": 1793019000, "expires": 1793019900, "triggers": 3, "flows_stopped": 11,
  "active": true, "ended": null, "ended_at": null, "ended_by": null, "simulated": true }
```

Times are Unix seconds. `ended` is `expired`, `lifted`, or `cleared`.

**Simulated addresses.** Simulation CSVs such as `simulation_test.csv` carry no
addresses, so in simulation mode the agent assigns them after classification,
only from reserved ranges: attacks come from 12 recurring attackers in the RFC
5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24); benign flows from
thousands of clients in 198.18.0.0/15 (RFC 2544); both go to 24 defended hosts
in 10.0.0.0/24. Addresses are keyed to the CSV row, so a row keeps its address
when the file wraps around. State reports `simulated_addresses: true`.

## Notifications

The agent keeps a feed of the latest 200 notifications:

| Kind | When | Title example |
|---|---|---|
| `containment` | an action starts or is lifted | `Blocked 203.0.113.7 (Simulated)` |
| `attack` | a `HIGH`, `CRITICAL`, or `UNKNOWN` attack with no containment action; at most once a minute per attack type | `Attack Detected: Password guessing` |
| `error` | detection starts failing (once per new error, not every cycle) | `Detection Stopped Working` |

```json
{ "id": 88, "time": 1793019000, "kind": "containment", "severity": "HIGH",
  "title": "Blocked 203.0.113.7 (Simulated)", "body": "neptune attack, high severity. ...",
  "action_id": 12, "detection_id": 1042 }
```

Each client filters by its own minimum severity (errors always pass):

- **Desktop:** the desktop app polls the feed every 5 seconds and shows system
  notifications (macOS Notification Center, `notify-send` on Linux; Windows shows
  alerts in the window only). More than 3 at once become one summary.
  Preferences are saved in `config.json`; the window also lists recent alerts.
- **Phone:** while the app is open it checks every 2 seconds and posts local
  notifications, shown as banners even in the foreground. In the background,
  iOS background refresh checks now and then (system-scheduled, often 15 minutes
  or more). Instant alerts on a locked phone need push through APNs (out of scope).

## Desktop relay API (`/api`, loopback only)

Every call needs `Authorization: Bearer LOCAL_TOKEN` (the token in the window's URL fragment).

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Window page |
| GET | `/api/connection` | `{"paired", "host", "port", "device_id", "role", "name", "reachable", "health" or "error"}` |
| POST | `/api/connection` | `{"code", "name"?}`: pair with an agent |
| DELETE | `/api/connection` | Unpair (removes this desktop from the agent if reachable) |
| GET, POST | `/api/preferences` | `{"system_notifications": bool, "notify_min_severity": "LOW"\|"MEDIUM"\|"HIGH"\|"CRITICAL"}` |
| any | `/api/<path>` | Forwarded to the agent as `/v1/<path>` with this desktop's token |

Relay errors: `503` not paired yet; `502` agent unreachable, certificate
mismatch, or this desktop was unlinked (each with a message saying what to do).

## iPhone app (`ios/`)

SwiftUI, iOS 17+, iPhone. Open `ios/LINDEF.xcodeproj`, choose your team under
Signing, and run. The app shows the same dashboard as the desktop (verdict,
Start/Stop/Clear, metrics, containment, alerts, detections, distributions,
monitoring sliders, log sharing, model details) in the paper design, with
Light, Dark, or Match the phone in Settings. Phones cannot switch the traffic
source, lift containment, or manage devices (see Roles).

Pairing uses the `lindef://` URL scheme: scanning the desktop's QR code with the
iPhone Camera app opens LINDEF, which always asks for confirmation (server and
certificate shown) before pairing. Pasting the code also works. The pairing is
kept in the Keychain (this device only).

The steps below are the contract any phone client (for example, a future Android app) follows.

1. Scan the QR code from the desktop (`POST /v1/pair` with role `phone`).
2. Parse `lindef://HOST:PORT?pair=CODE&fp=FINGERPRINT`.
3. Open HTTPS to `HOST:PORT` and accept the server certificate **only if** its
   SHA-256 fingerprint (of the DER-encoded certificate) equals `FINGERPRINT`
   (iOS: a `URLSession` delegate handling `serverTrust`; Android: an OkHttp
   `CertificatePinner` or a custom `X509TrustManager`).
4. `POST /v1/pair/claim {"code": CODE, "name": device name}` and store the token
   and fingerprint in the Keychain (iOS) or Keystore (Android).
5. Use `Authorization: Bearer TOKEN` on every call. On `401`, show "This phone
   was unlinked. Scan a new code from the desktop."
6. The agent must be reachable from the phone: same network, VPN, or a forwarded port.

## Detection loop

- Runs on a daemon thread. Each cycle: if running, take one batch, classify it, number and append the detections, save the log to `attack_log.csv`, then wait `refresh_seconds`.
- **Simulation:** `rows_per_step` rows per cycle, continuing where the last batch ended, wrapping to the start. The CSV is re-read only when the file changes.
- **Live:** capture `capture_duration` seconds with TShark, convert with CICFlowMeter, classify every flow. The CICFlowMeter CSV is deleted after reading, so flows are never classified twice. Only the newest 20 pcaps are kept. A capture with no flows is a quiet cycle, not an error.
- The binary model scores the whole batch in one call; the attack classifier runs once on all flagged flows.
- Errors appear as `error` in State; the loop retries next cycle and clears the error on success.
- Start and settings changes wake the loop immediately. Clear Logs discards a batch already being processed.
- One lock guards settings and the log; capture and classification run outside it, so the API stays responsive.

## Out of scope / next steps

- **Real enforcement.** Containment is simulated. Applying it (firewall rules from `Source IP`) needs a separate, opt-in design.
- **Push notifications to a locked phone.** Needs APNs/FCM through a relay service; until then the app alerts while open and on background refresh.
- **Android app.**
- **Several agents per desktop or phone.**

