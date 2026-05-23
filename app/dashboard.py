"""
LINDEF Streamlit Dashboard

This dashboard can run in two modes:
1. Simulation mode: reads an existing CSV such as simulation_test.csv.
2. Live/CICFlowMeter mode: captures traffic with TShark, converts the pcap to
   flow features with CICFlowMeter, aligns the columns to the training feature
   list, and classifies each flow.

Important note:
CICFlowMeter does not directly generate every NSL-KDD or UNSW-NB15 feature.
Because the LINDEF model was trained on a combined feature space, this app
matches live/simulation data to feature_columns.pkl and fills missing columns
with saved medians when available. If medians are unavailable, it uses 0.
"""

import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# -----------------------------------------------------------------------------
# Page setup
# -----------------------------------------------------------------------------

st.set_page_config(page_title="LINDEF Live IDS Dashboard", layout="wide")
st.title("LINDEF Live Intrusion Detection Dashboard")
st.caption("Lightweight real-time network intrusion detection and attack classification")

# -----------------------------------------------------------------------------
# File paths and app settings
# -----------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# These paths assume the app/ folder is next to models/, results/, and data/.
# If you keep everything in one folder, change these paths to match your setup.
MODEL_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"
LIVE_PCAP_DIR = PROJECT_ROOT / "live_pcaps"
LIVE_CSV_DIR = PROJECT_ROOT / "live_csvs"
LOG_FILE = PROJECT_ROOT / "attack_log.csv"

BINARY_MODEL_PATH = MODEL_DIR / "binary_model.pkl"
MULTI_MODEL_PATH = MODEL_DIR / "class_model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
FEATURE_COLUMNS_PATH = MODEL_DIR / "feature_columns.pkl"
FEATURE_MEDIANS_PATH = MODEL_DIR / "feature_medians.npy"

DEFAULT_SIMULATION_CSV = PROJECT_ROOT / "results" / "simulation_test.csv"

LIVE_PCAP_DIR.mkdir(exist_ok=True)
LIVE_CSV_DIR.mkdir(exist_ok=True)

# -----------------------------------------------------------------------------
# Response logic
# -----------------------------------------------------------------------------

ATTACK_TO_ACTION = {
    # DoS-style attacks
    "neptune": "BLOCK_IP",
    "smurf": "BLOCK_IP",
    "back": "BLOCK_IP",
    "pod": "BLOCK_IP",
    "teardrop": "BLOCK_IP",
    "apache2": "BLOCK_IP",
    "mailbomb": "BLOCK_IP",
    "land": "BLOCK_IP",

    # Probe / scanning attacks
    "satan": "BLOCK_IP",
    "nmap": "BLOCK_IP",
    "portsweep": "BLOCK_IP",
    "ipsweep": "BLOCK_IP",
    "mscan": "BLOCK_IP",
    "saint": "BLOCK_IP",

    # Credential or access attempts
    "guess_passwd": "THROTTLE_IP",
    "ftp_write": "THROTTLE_IP",
    "imap": "THROTTLE_IP",
    "phf": "THROTTLE_IP",
    "multihop": "THROTTLE_IP",
    "warezmaster": "THROTTLE_IP",
    "warezclient": "THROTTLE_IP",
    "snmpguess": "THROTTLE_IP",
    "snmpgetattack": "THROTTLE_IP",

    # Higher-risk host compromise or tunneling behavior
    "httptunnel": "ISOLATE_HOST",
    "rootkit": "ISOLATE_HOST",
    "buffer_overflow": "ISOLATE_HOST",
    "loadmodule": "ISOLATE_HOST",
    "perl": "ISOLATE_HOST",
    "xterm": "ISOLATE_HOST",
    "ps": "ISOLATE_HOST",
    "sqlattack": "ISOLATE_HOST",

    # Normal traffic
    "normal": "ALLOW",
    "benign": "ALLOW",
}

SEVERITY_MAP = {
    # DoS-style attacks
    "neptune": "HIGH",
    "smurf": "HIGH",
    "back": "HIGH",
    "pod": "HIGH",
    "teardrop": "HIGH",
    "apache2": "HIGH",
    "mailbomb": "HIGH",
    "land": "HIGH",

    # Probe / scanning attacks
    "satan": "LOW",
    "nmap": "LOW",
    "portsweep": "LOW",
    "ipsweep": "LOW",
    "mscan": "LOW",
    "saint": "LOW",

    # Credential or access attempts
    "guess_passwd": "HIGH",
    "ftp_write": "MEDIUM",
    "imap": "MEDIUM",
    "phf": "MEDIUM",
    "multihop": "HIGH",
    "warezmaster": "HIGH",
    "warezclient": "HIGH",
    "snmpguess": "HIGH",
    "snmpgetattack": "HIGH",

    # Higher-risk host compromise or tunneling behavior
    "httptunnel": "CRITICAL",
    "rootkit": "CRITICAL",
    "buffer_overflow": "CRITICAL",
    "loadmodule": "CRITICAL",
    "perl": "CRITICAL",
    "xterm": "CRITICAL",
    "ps": "CRITICAL",
    "sqlattack": "CRITICAL",

    # Normal traffic
    "normal": "NONE",
    "benign": "NONE",
}

INVALID_ATTACK_OUTPUTS = {"0", "1", 0, 1, "normal", "benign", "NORMAL", "BENIGN"}

# -----------------------------------------------------------------------------
# Cached loading functions
# -----------------------------------------------------------------------------

@st.cache_resource
def load_resources():
    """Load trained models and feature metadata once per app session."""
    required_files = [
        BINARY_MODEL_PATH,
        MULTI_MODEL_PATH,
        SCALER_PATH,
        FEATURE_COLUMNS_PATH,
    ]

    missing = [str(path) for path in required_files if not path.exists()]
    if missing:
        st.error("Missing required model files:")
        for path in missing:
            st.code(path)
        st.stop()

    binary_model = joblib.load(BINARY_MODEL_PATH)
    multi_model = joblib.load(MULTI_MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

    feature_medians = None
    if FEATURE_MEDIANS_PATH.exists():
        feature_medians = np.load(FEATURE_MEDIANS_PATH, allow_pickle=True)

    return binary_model, multi_model, scaler, feature_columns, feature_medians


binary_model, multi_model, scaler, feature_columns, feature_medians = load_resources()

# -----------------------------------------------------------------------------
# Feature alignment
# -----------------------------------------------------------------------------

def clean_feature_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply lightweight cleanup before aligning data to the training features.

    This does not recreate the entire training preprocessing pipeline. It only
    handles the live/simulation cases: remove extra spaces, replace infinities,
    and coerce values into numeric form for the trained scaler/model.
    """
    df = df.copy()
    df.columns = df.columns.astype(str).str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop obvious non-feature columns if CICFlowMeter includes them.
    drop_keywords = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
    drop_cols = [
        col for col in df.columns
        if any(keyword in str(col) for keyword in drop_keywords)
    ]
    df.drop(columns=drop_cols, inplace=True, errors="ignore")

    # Some CICFlowMeter exports use a label column. The model should not see it.
    df.drop(columns=["Label", "attack_type", "attack_cat", "binary_label", "multi_label", "dataset"],
            inplace=True,
            errors="ignore")

    # Match the packet_rate feature used during training when possible.
    required_packet_cols = {"Flow Duration", "Total Fwd Packets", "Total Backward Packets"}
    if required_packet_cols.issubset(df.columns):
        total_packets = df["Total Fwd Packets"] + df["Total Backward Packets"]
        safe_duration = df["Flow Duration"].replace(0, 1)
        df["packet_rate"] = total_packets / safe_duration

    # Convert everything possible into numbers. Anything that cannot be converted
    # becomes NaN and will be filled during alignment.
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def build_fill_values(feature_columns, feature_medians):
    """
    Build per-feature fill values.

    feature_medians.npy from the training code is saved as an array, not a named
    Series. If its length matches feature_columns, use it directly. Otherwise,
    fall back to 0 for every missing feature.
    """
    if feature_medians is not None and len(feature_medians) == len(feature_columns):
        return dict(zip(feature_columns, feature_medians))

    return {col: 0 for col in feature_columns}


def align_features(df: pd.DataFrame) -> pd.DataFrame:
    """Force live/simulation data into the exact feature order used in training."""
    df = clean_feature_dataframe(df)
    fill_values = build_fill_values(feature_columns, feature_medians)

    aligned = pd.DataFrame(index=df.index)

    for col in feature_columns:
        if col in df.columns:
            aligned[col] = df[col]
        else:
            aligned[col] = fill_values.get(col, 0)

    aligned.fillna(fill_values, inplace=True)
    aligned.fillna(0, inplace=True)

    return aligned

# -----------------------------------------------------------------------------
# CICFlowMeter / TShark helpers
# -----------------------------------------------------------------------------

def run_command(command, timeout=60):
    """Run a shell command and return whether it worked plus the output."""
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=True,
        )
        ok = result.returncode == 0
        output = result.stdout.strip() or result.stderr.strip()
        return ok, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out."
    except Exception as exc:
        return False, str(exc)


def capture_pcap(tshark_path: str, interface_id: str, duration_seconds: int) -> Path | None:
    """Capture a short pcap file using TShark."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = LIVE_PCAP_DIR / f"capture_{timestamp}.pcap"

    command = (
        f'"{tshark_path}" -i {interface_id} '
        f'-a duration:{duration_seconds} '
        f'-w "{pcap_path}"'
    )

    ok, output = run_command(command, timeout=duration_seconds + 20)

    if not ok:
        st.warning("TShark capture failed.")
        st.code(output)
        return None

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        st.warning("TShark ran, but no pcap data was captured.")
        return None

    return pcap_path


def run_cicflowmeter(cicflowmeter_command: str, pcap_path: Path) -> Path | None:
    """
    Convert a pcap file into CICFlowMeter CSV features.

    The command is configurable because CICFlowMeter installations vary. Use
    placeholders in the sidebar command:
        {input}  -> pcap file path
        {output} -> output CSV folder
    """
    before_files = set(LIVE_CSV_DIR.glob("*.csv"))

    command = cicflowmeter_command.format(
        input=str(pcap_path),
        output=str(LIVE_CSV_DIR),
    )

    ok, output = run_command(command, timeout=120)

    if not ok:
        st.warning("CICFlowMeter failed.")
        st.code(output)
        return None

    after_files = set(LIVE_CSV_DIR.glob("*.csv"))
    new_files = sorted(list(after_files - before_files), key=lambda p: p.stat().st_mtime, reverse=True)

    if new_files:
        return new_files[0]

    # Some CICFlowMeter versions overwrite or reuse filenames, so fall back to
    # the newest CSV in the folder.
    all_csvs = sorted(LIVE_CSV_DIR.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if all_csvs:
        return all_csvs[0]

    st.warning("CICFlowMeter ran, but no CSV output was found.")
    return None

# -----------------------------------------------------------------------------
# Prediction logic
# -----------------------------------------------------------------------------

def classify_flows(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Align features, scale them, and classify each flow."""
    if raw_df.empty:
        return pd.DataFrame()

    aligned_df = align_features(raw_df)
    X_scaled = scaler.transform(aligned_df.to_numpy())

    binary_preds = binary_model.predict(X_scaled)
    binary_probs = None

    if hasattr(binary_model, "predict_proba"):
        binary_probs = binary_model.predict_proba(X_scaled)[:, 1]

    rows = []

    for i, pred_bin in enumerate(binary_preds):
        attack_probability = float(binary_probs[i]) if binary_probs is not None else np.nan

        if pred_bin == 0:
            rows.append({
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Status": "BENIGN",
                "Attack": "normal",
                "Attack Probability": attack_probability,
                "Severity": "NONE",
                "Response": "ALLOW",
            })
            continue

        pred_multi = multi_model.predict(X_scaled[i].reshape(1, -1))[0]
        attack = str(pred_multi)

        # If the multi-class model returns a normal/invalid class, treat it as
        # benign to avoid fake attack labels in the dashboard.
        if attack in INVALID_ATTACK_OUTPUTS:
            rows.append({
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Status": "BENIGN",
                "Attack": "normal",
                "Attack Probability": attack_probability,
                "Severity": "NONE",
                "Response": "ALLOW",
            })
            continue

        rows.append({
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Status": "ATTACK",
            "Attack": attack,
            "Attack Probability": attack_probability,
            "Severity": SEVERITY_MAP.get(attack, "UNKNOWN"),
            "Response": ATTACK_TO_ACTION.get(attack, "MONITOR"),
        })

    return pd.DataFrame(rows)


def append_logs(new_logs: pd.DataFrame):
    """Add new detections to the session log and save a copy to disk."""
    if new_logs.empty:
        return

    st.session_state.logs.extend(new_logs.to_dict("records"))
    st.session_state.logs = st.session_state.logs[-500:]

    log_df = pd.DataFrame(st.session_state.logs)
    log_df.to_csv(LOG_FILE, index=False)

# -----------------------------------------------------------------------------
# Session state
# -----------------------------------------------------------------------------

if "running" not in st.session_state:
    st.session_state.running = False

if "logs" not in st.session_state:
    st.session_state.logs = []

if "simulation_idx" not in st.session_state:
    st.session_state.simulation_idx = 0

if "last_error" not in st.session_state:
    st.session_state.last_error = ""

# -----------------------------------------------------------------------------
# Sidebar controls
# -----------------------------------------------------------------------------

st.sidebar.header("Controls")

mode = st.sidebar.radio(
    "Input mode",
    ["Simulation CSV", "Live Capture with CICFlowMeter"],
)

refresh_seconds = st.sidebar.slider("Refresh speed", 0.5, 10.0, 2.0, 0.5)
rows_per_step = st.sidebar.slider("Flows per refresh", 1, 100, 10)

if mode == "Simulation CSV":
    simulation_csv_path = st.sidebar.text_input(
        "Simulation CSV path",
        value=str(DEFAULT_SIMULATION_CSV),
    )
else:
    st.sidebar.subheader("TShark")
    tshark_path = st.sidebar.text_input(
        "TShark path",
        value="tshark",
        help="Use tshark if it is on PATH, or paste the full path to tshark.exe.",
    )
    interface_id = st.sidebar.text_input(
        "Interface ID",
        value="1",
        help="Run tshark -D in a terminal to see interface numbers.",
    )
    capture_duration = st.sidebar.slider("Capture duration per refresh", 2, 20, 5)

    st.sidebar.subheader("CICFlowMeter")
    cicflowmeter_command = st.sidebar.text_area(
        "CICFlowMeter command",
        value='CICFlowMeter.bat "{input}" "{output}"',
        help="Use {input} for the pcap path and {output} for the output CSV folder.",
    )

col_start, col_stop, col_clear = st.columns(3)

if col_start.button("Start", use_container_width=True):
    st.session_state.running = True

if col_stop.button("Stop", use_container_width=True):
    st.session_state.running = False

if col_clear.button("Clear Logs", use_container_width=True):
    st.session_state.logs = []
    st.session_state.simulation_idx = 0
    if LOG_FILE.exists():
        LOG_FILE.unlink()

# -----------------------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------------------

st_autorefresh(interval=int(refresh_seconds * 1000), key="lindef_refresh")

if st.session_state.running:
    if mode == "Simulation CSV":
        path = Path(simulation_csv_path)

        if not path.exists():
            st.session_state.last_error = f"Simulation CSV not found: {path}"
        else:
            raw_df = pd.read_csv(path)

            if raw_df.empty:
                st.session_state.last_error = "Simulation CSV is empty."
            else:
                start = st.session_state.simulation_idx
                end = start + rows_per_step

                if end <= len(raw_df):
                    batch_df = raw_df.iloc[start:end]
                else:
                    # Wrap around to keep the demo running.
                    first_part = raw_df.iloc[start:]
                    second_part = raw_df.iloc[: end % len(raw_df)]
                    batch_df = pd.concat([first_part, second_part], ignore_index=True)

                st.session_state.simulation_idx = end % len(raw_df)
                new_logs = classify_flows(batch_df)
                append_logs(new_logs)
                st.session_state.last_error = ""

    else:
        pcap_path = capture_pcap(tshark_path, interface_id, capture_duration)

        if pcap_path is not None:
            csv_path = run_cicflowmeter(cicflowmeter_command, pcap_path)

            if csv_path is not None and csv_path.exists():
                raw_df = pd.read_csv(csv_path)
                new_logs = classify_flows(raw_df)
                append_logs(new_logs)
                st.session_state.last_error = ""
            else:
                st.session_state.last_error = "No CICFlowMeter CSV was created."

# -----------------------------------------------------------------------------
# Dashboard display
# -----------------------------------------------------------------------------

logs_df = pd.DataFrame(st.session_state.logs)

status_box_1, status_box_2, status_box_3, status_box_4 = st.columns(4)

if logs_df.empty:
    total_flows = 0
    attack_flows = 0
    benign_flows = 0
    latest_status = "Waiting"
else:
    total_flows = len(logs_df)
    attack_flows = int((logs_df["Status"] == "ATTACK").sum())
    benign_flows = int((logs_df["Status"] == "BENIGN").sum())
    latest_status = logs_df.iloc[-1]["Status"]

status_box_1.metric("Total Flows Checked", total_flows)
status_box_2.metric("Detected Attacks", attack_flows)
status_box_3.metric("Benign Flows", benign_flows)
status_box_4.metric("Latest Status", latest_status)

if st.session_state.last_error:
    st.warning(st.session_state.last_error)

st.divider()

if logs_df.empty:
    st.info("Start the dashboard to begin processing traffic.")
else:
    st.subheader("Recent Detections")

    display_df = logs_df.tail(50).copy()
    if "Attack Probability" in display_df.columns:
        display_df["Attack Probability"] = display_df["Attack Probability"].round(4)

    st.dataframe(display_df, use_container_width=True)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Attack vs. Benign")
        st.bar_chart(logs_df["Status"].value_counts(), use_container_width=True)

    with col2:
        st.subheader("Severity Distribution")
        st.bar_chart(logs_df["Severity"].value_counts(), use_container_width=True)

    col3, col4 = st.columns(2)

    with col3:
        st.subheader("Attack Types")
        attack_counts = logs_df[logs_df["Attack"] != "normal"]["Attack"].value_counts()
        if attack_counts.empty:
            st.info("No attack types detected yet.")
        else:
            st.bar_chart(attack_counts, use_container_width=True)

    with col4:
        st.subheader("Recommended Responses")
        st.bar_chart(logs_df["Response"].value_counts(), use_container_width=True)

    st.download_button(
        label="Download Detection Log",
        data=logs_df.to_csv(index=False),
        file_name="attack_log.csv",
        mime="text/csv",
    )

st.divider()

with st.expander("Model and feature details"):
    st.write("Binary model:", BINARY_MODEL_PATH)
    st.write("Multi-class model:", MULTI_MODEL_PATH)
    st.write("Scaler:", SCALER_PATH)
    st.write("Number of expected features:", len(feature_columns))
    st.write("Feature medians loaded:", feature_medians is not None)

    if st.checkbox("Show expected feature columns"):
        st.write(feature_columns)
