"""
LINDEF detection engine.

Loads the trained models, turns simulation or live traffic into flow
features, and classifies each flow. There is no UI code here; server.py
drives this module and the desktop/phone frontend displays the results.

Two input sources are supported:
1. Simulation: rows from an existing CSV such as simulation_test.csv.
2. Live/CICFlowMeter: captures traffic with TShark, converts the pcap to
   flow features with CICFlowMeter, then classifies each flow.

Important note:
CICFlowMeter does not directly generate every NSL-KDD or UNSW-NB15 feature.
Because the LINDEF model was trained on a combined feature space, incoming
data is matched to feature_columns.pkl and missing columns are filled with
saved medians when available. If medians are unavailable, 0 is used.
"""

import subprocess
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# -----------------------------------------------------------------------------
# File paths
# -----------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# These paths assume the app/ folder is next to models/, results/, and data/.
MODEL_DIR = PROJECT_ROOT / "models"
LIVE_PCAP_DIR = PROJECT_ROOT / "live_pcaps"
LIVE_CSV_DIR = PROJECT_ROOT / "live_csvs"
LOG_FILE = PROJECT_ROOT / "attack_log.csv"

BINARY_MODEL_PATH = MODEL_DIR / "binary_model.pkl"
MULTI_MODEL_PATH = MODEL_DIR / "class_model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
FEATURE_COLUMNS_PATH = MODEL_DIR / "feature_columns.pkl"
FEATURE_MEDIANS_PATH = MODEL_DIR / "feature_medians.npy"

DEFAULT_SIMULATION_CSV = PROJECT_ROOT / "results" / "simulation_test.csv"

KEEP_CAPTURES = 20  # newest pcaps kept for review; older ones are deleted

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
# Model loading
# -----------------------------------------------------------------------------

REQUIRED_MODEL_FILES = [BINARY_MODEL_PATH, MULTI_MODEL_PATH, SCALER_PATH, FEATURE_COLUMNS_PATH]


def missing_model_files() -> list[str]:
    """Return the required model files that are not on disk yet."""
    return [str(path) for path in REQUIRED_MODEL_FILES if not path.exists()]


def load_models() -> dict:
    """Load trained models and feature metadata. Call once at startup."""
    feature_medians = None
    if FEATURE_MEDIANS_PATH.exists():
        feature_medians = np.load(FEATURE_MEDIANS_PATH, allow_pickle=True)

    return {
        "binary": joblib.load(BINARY_MODEL_PATH),
        "multi": joblib.load(MULTI_MODEL_PATH),
        "scaler": joblib.load(SCALER_PATH),
        "feature_columns": list(joblib.load(FEATURE_COLUMNS_PATH)),
        "feature_medians": feature_medians,
    }

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


def align_features(df: pd.DataFrame, models: dict) -> pd.DataFrame:
    """Force live/simulation data into the exact feature order used in training."""
    df = clean_feature_dataframe(df)
    feature_columns = models["feature_columns"]
    fill_values = build_fill_values(feature_columns, models["feature_medians"])

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


def prune_old_files(folder: Path, pattern: str, keep: int):
    """Delete all but the newest `keep` files so live mode cannot fill the disk."""
    files = sorted(folder.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        old.unlink(missing_ok=True)


def capture_pcap(tshark_path: str, interface_id: str, duration_seconds: int) -> Path:
    """Capture a short pcap file using TShark. Raises RuntimeError on failure."""
    LIVE_PCAP_DIR.mkdir(exist_ok=True)
    prune_old_files(LIVE_PCAP_DIR, "*.pcap", KEEP_CAPTURES - 1)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = LIVE_PCAP_DIR / f"capture_{timestamp}.pcap"

    command = (
        f'"{tshark_path}" -i {interface_id} '
        f'-a duration:{duration_seconds} '
        f'-w "{pcap_path}"'
    )

    ok, output = run_command(command, timeout=duration_seconds + 20)

    if not ok:
        raise RuntimeError(f"TShark capture failed.\n{output}")

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        raise RuntimeError("TShark ran, but no pcap data was captured.")

    return pcap_path


def run_cicflowmeter(cicflowmeter_command: str, pcap_path: Path) -> Path:
    """
    Convert a pcap file into CICFlowMeter CSV features. Raises RuntimeError on failure.

    The command is configurable because CICFlowMeter installations vary. Use
    placeholders in the command:
        {input}  -> pcap file path
        {output} -> output CSV folder
    """
    LIVE_CSV_DIR.mkdir(exist_ok=True)
    before_files = set(LIVE_CSV_DIR.glob("*.csv"))

    command = cicflowmeter_command.format(
        input=str(pcap_path),
        output=str(LIVE_CSV_DIR),
    )

    ok, output = run_command(command, timeout=120)

    if not ok:
        raise RuntimeError(f"CICFlowMeter failed.\n{output}")

    after_files = set(LIVE_CSV_DIR.glob("*.csv"))
    new_files = sorted(list(after_files - before_files), key=lambda p: p.stat().st_mtime, reverse=True)

    if new_files:
        return new_files[0]

    # Some CICFlowMeter versions overwrite or reuse filenames, so fall back to
    # the newest CSV in the folder.
    all_csvs = sorted(LIVE_CSV_DIR.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if all_csvs:
        return all_csvs[0]

    raise RuntimeError("CICFlowMeter ran, but no CSV output was found.")

# -----------------------------------------------------------------------------
# Prediction logic
# -----------------------------------------------------------------------------

def classify_flows(raw_df: pd.DataFrame, models: dict) -> list[dict]:
    """Align features, scale them, and classify each flow into a log record."""
    if raw_df.empty:
        return []

    aligned_df = align_features(raw_df, models)
    X_scaled = models["scaler"].transform(aligned_df.to_numpy())

    binary_model = models["binary"]
    binary_preds = binary_model.predict(X_scaled)
    binary_probs = None

    if hasattr(binary_model, "predict_proba"):
        binary_probs = binary_model.predict_proba(X_scaled)[:, 1]

    # Run the attack classifier once on every flagged flow instead of once per
    # flow; live captures can contain thousands of flows.
    attacks = np.full(len(binary_preds), "normal", dtype=object)
    flagged = np.flatnonzero(binary_preds != 0)
    if len(flagged):
        attacks[flagged] = [str(a) for a in models["multi"].predict(X_scaled[flagged])]

    rows = []
    timestamp = datetime.now().strftime("%H:%M:%S")

    for i, attack in enumerate(attacks):
        # None (not NaN) so the record stays valid JSON for the frontend.
        attack_probability = float(binary_probs[i]) if binary_probs is not None else None

        # If the multi-class model returns a normal/invalid class, treat it as
        # benign to avoid fake attack labels in the dashboard.
        if attack in INVALID_ATTACK_OUTPUTS:
            rows.append({
                "Time": timestamp,
                "Status": "BENIGN",
                "Attack": "normal",
                "Attack Probability": attack_probability,
                "Severity": "NONE",
                "Response": "ALLOW",
            })
            continue

        rows.append({
            "Time": timestamp,
            "Status": "ATTACK",
            "Attack": attack,
            "Attack Probability": attack_probability,
            "Severity": SEVERITY_MAP.get(attack, "UNKNOWN"),
            "Response": ATTACK_TO_ACTION.get(attack, "MONITOR"),
        })

    return rows
