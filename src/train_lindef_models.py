"""
LINDEF Model Training Pipeline

This script trains two Random Forest models for LINDEF:
1. Binary model: normal traffic vs. attack traffic
2. Multi-class model: attack type classification

Local/GitHub version:
- Run from a normal Python environment.
- Install dependencies with: pip install -r requirements.txt
- Pass dataset paths through command-line arguments.
"""

import argparse
import glob
import os
import time
import warnings
import zipfile
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import psutil
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize

warnings.filterwarnings("ignore")

# -----------------------------
# Project settings
# -----------------------------

RANDOM_STATE = 42
MAX_SAMPLE_ROWS = 200_000
CHUNK_SIZE = 100_000
MIN_CLASS_COUNT = 6

NORMAL_LABELS = {"NORMAL", "BENIGN"}

MODEL_DROP_COLUMNS = [
    "binary_label",
    "multi_label",
    "attack_type",
    "Label",
    "attack_cat",
    "dataset",
    "Destination Port",
]

LEAKAGE_COLUMN_KEYWORDS = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
]


# -----------------------------
# Data loading
# -----------------------------

def extract_cic_zip(cic_zip_path: Path, extract_dir: Path) -> list[str]:
    """Extract the CIC-IDS zip file and return all CSV file paths."""
    extract_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(cic_zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_dir)

    csv_files = glob.glob(str(extract_dir / "**" / "*.csv"), recursive=True)

    if not csv_files:
        raise FileNotFoundError("No CIC-IDS CSV files were found after extraction.")

    return csv_files


def load_cic_ids(csv_files: list[str]) -> pd.DataFrame:
    """Load CIC-IDS CSV files with chunks to reduce memory pressure."""
    cic_frames = []

    for file_path in csv_files:
        print(f"Loading {os.path.basename(file_path)}")
        chunks = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
        temp_df = pd.concat(chunks, ignore_index=True)
        cic_frames.append(temp_df)

    cic_ids_df = pd.concat(cic_frames, ignore_index=True)

    # CIC-IDS column names often include extra spaces.
    cic_ids_df.columns = cic_ids_df.columns.str.strip()
    cic_ids_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    cic_ids_df.dropna(inplace=True)

    print("CIC-IDS final shape:", cic_ids_df.shape)
    return cic_ids_df


def load_nsl_kdd(nsl_train_path: Path, nsl_test_path: Path) -> pd.DataFrame:
    """Load and combine NSL-KDD train/test files."""
    nsl_train = pd.read_csv(nsl_train_path, header=None)
    nsl_test = pd.read_csv(nsl_test_path, header=None)

    nsl = pd.concat([nsl_train, nsl_test], ignore_index=True)
    nsl.rename(columns={41: "attack_type"}, inplace=True)
    nsl["dataset"] = "NSL-KDD"

    return nsl


def load_unsw_nb15(unsw_train_path: Path, unsw_test_path: Path) -> pd.DataFrame:
    """Load and combine UNSW-NB15 train/test files."""
    unsw_train = pd.read_csv(unsw_train_path)
    unsw_test = pd.read_csv(unsw_test_path)

    unsw = pd.concat([unsw_train, unsw_test], ignore_index=True)
    unsw.rename(columns={"label": "attack_type"}, inplace=True)
    unsw["dataset"] = "UNSW-NB15"

    return unsw


# -----------------------------
# Preprocessing
# -----------------------------

def reduce_memory_usage(df: pd.DataFrame) -> pd.DataFrame:
    """Downcast numeric columns to help avoid RAM issues."""
    for col in df.select_dtypes(include=["float64"]).columns:
        df[col] = df[col].astype("float32")

    for col in df.select_dtypes(include=["int64"]).columns:
        df[col] = df[col].astype("int32")

    return df


def remove_leakage_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Remove identifiers and timestamp columns that should not be model features."""
    drop_cols = [
        col
        for col in df.columns
        if any(keyword in str(col) for keyword in LEAKAGE_COLUMN_KEYWORDS)
    ]

    df.drop(columns=drop_cols, inplace=True, errors="ignore")
    return df


def add_packet_rate_feature(df: pd.DataFrame) -> pd.DataFrame:
    """Create packet_rate when the required CIC-style flow columns exist."""
    required_cols = {"Flow Duration", "Total Fwd Packets", "Total Backward Packets"}

    if required_cols.issubset(df.columns):
        total_packets = df["Total Fwd Packets"] + df["Total Backward Packets"]
        safe_duration = df["Flow Duration"].replace(0, 1)
        df["packet_rate"] = total_packets / safe_duration

    return df


def create_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Create binary and multi-class labels."""
    df["binary_label"] = df["attack_type"].apply(
        lambda x: 0 if str(x).upper() in NORMAL_LABELS else 1
    )
    df["multi_label"] = df["attack_type"].astype(str)

    return df


def encode_categorical_features(df: pd.DataFrame):
    """
    Encode categorical feature columns.

    The original workflow saved only the last LabelEncoder as labelEncoder.pkl.
    This script keeps that behavior for compatibility, but also returns all
    encoders in case you want to save them later.
    """
    encoders = {}
    last_encoder = None

    cat_cols = df.select_dtypes(include=["object"]).columns

    for col in cat_cols:
        if col in ["attack_type", "multi_label"]:
            continue

        df[col] = df[col].astype(str)
        encoder = LabelEncoder()
        df[col] = encoder.fit_transform(df[col])

        encoders[col] = encoder
        last_encoder = encoder

    return df, encoders, last_encoder


def prepare_dataset(
    nsl_train_path: Path,
    nsl_test_path: Path,
    unsw_train_path: Path,
    unsw_test_path: Path,
    cic_ids_df: pd.DataFrame,
):
    """Combine all datasets, clean data, create labels, and split features/targets."""
    nsl = load_nsl_kdd(nsl_train_path, nsl_test_path)
    unsw = load_unsw_nb15(unsw_train_path, unsw_test_path)

    combined_df = pd.concat([nsl, unsw, cic_ids_df], ignore_index=True)
    print("Original dataset size:", combined_df.shape)

    combined_df = combined_df.sample(
        min(MAX_SAMPLE_ROWS, len(combined_df)),
        random_state=RANDOM_STATE,
    )
    print("Sampled dataset size:", combined_df.shape)

    combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined_df = combined_df.dropna(subset=["attack_type"])
    combined_df.fillna(0, inplace=True)
    combined_df.drop_duplicates(inplace=True)

    combined_df = reduce_memory_usage(combined_df)
    combined_df = remove_leakage_columns(combined_df)
    combined_df = add_packet_rate_feature(combined_df)
    combined_df = create_labels(combined_df)
    combined_df, encoders, last_encoder = encode_categorical_features(combined_df)

    X = combined_df.drop(columns=MODEL_DROP_COLUMNS, errors="ignore")
    X.columns = X.columns.astype(str)

    y_binary = combined_df["binary_label"]
    y_multi = combined_df["multi_label"]

    print("Dataset ready. Shape:", X.shape)
    return combined_df, X, y_binary, y_multi, encoders, last_encoder


def split_and_scale_features(X, y_binary, y_multi):
    """Create the train/test split and scale features."""
    X_train, X_test, y_bin_train, y_bin_test, y_multi_train, y_multi_test = train_test_split(
        X,
        y_binary,
        y_multi,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y_binary,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print(
        "Preprocessing complete. X_train shape:",
        X_train_scaled.shape,
        "X_test shape:",
        X_test_scaled.shape,
    )

    return X_train_scaled, X_test_scaled, y_bin_train, y_bin_test, y_multi_train, y_multi_test, scaler


# -----------------------------
# Training
# -----------------------------

def train_binary_model(X_train, y_train):
    """Train the normal-vs-attack classifier."""
    print("\n--- Binary Classification ---")

    smote = SMOTE(random_state=RANDOM_STATE)
    X_balanced, y_balanced = smote.fit_resample(X_train, y_train)

    print("Binary SMOTE applied. Balanced class counts:")
    print(pd.Series(y_balanced).value_counts())

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_balanced, y_balanced)

    print("Binary model trained.")
    return model, X_balanced, y_balanced


def train_multi_class_model(X_train, y_train):
    """Train the attack-type classifier using classes with enough samples for SMOTE."""
    print("\n--- Multi-Class Classification ---")

    class_counts = y_train.value_counts()
    valid_classes = class_counts[class_counts >= MIN_CLASS_COUNT].index.tolist()

    mask = y_train.isin(valid_classes)
    X_train_filtered = X_train[mask]
    y_train_filtered = y_train[mask]

    print(
        f"Training multi-class on {len(valid_classes)} classes "
        f"(classes with >= {MIN_CLASS_COUNT} samples)."
    )

    smote = SMOTE(random_state=RANDOM_STATE)
    X_balanced, y_balanced = smote.fit_resample(X_train_filtered, y_train_filtered)

    print("Multi-class SMOTE applied. Balanced class counts:")
    print(pd.Series(y_balanced).value_counts())

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_balanced, y_balanced)

    print("Multi-class model trained.")
    return model, X_train_filtered, y_train_filtered, X_balanced, y_balanced


# -----------------------------
# Evaluation
# -----------------------------

def evaluate_model(model, X_test, y_test, dataset_name="Dataset", binary=False):
    """Print accuracy, precision, recall, F1, and false positive rate."""
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    if binary:
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0
        fpr_str = f"{fpr * 100:.2f}%"
    else:
        fpr_values = []

        for cls in np.unique(y_test):
            y_test_bin = (y_test == cls).astype(int)
            y_pred_bin = (y_pred == cls).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_test_bin, y_pred_bin).ravel()
            fpr_values.append(fp / (fp + tn) if (fp + tn) else 0)

        fpr = np.mean(fpr_values)
        fpr_str = f"{fpr * 100:.2f}% (average)"

    print(f"\n--- {dataset_name} Model Performance ---")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")
    print(f"FPR      : {fpr_str}")

    return accuracy, precision, recall, f1, fpr


def filter_multi_class_test_set(X_test, y_test, trained_classes):
    """Keep only test samples from classes seen during multi-class training."""
    mask = y_test.isin(trained_classes)
    return X_test[mask], y_test[mask]


def measure_performance(model, X_test):
    """Measure average per-flow latency, rough CPU usage, and RAM difference."""
    latencies = []
    cpu_percentages = []

    mem_before = psutil.virtual_memory().used / (1024 * 1024)

    for i in range(len(X_test)):
        if isinstance(X_test, np.ndarray):
            packet = X_test[i].reshape(1, -1)
        else:
            packet = X_test.iloc[i].values.reshape(1, -1)

        psutil.cpu_percent(interval=None)
        start = time.perf_counter()
        model.predict(packet)
        end = time.perf_counter()

        latencies.append(end - start)
        cpu_percentages.append(psutil.cpu_percent(interval=None))

    mem_after = psutil.virtual_memory().used / (1024 * 1024)

    avg_latency_ms = np.mean(latencies) * 1000
    avg_cpu = np.mean(cpu_percentages)
    ram_used = mem_after - mem_before

    return avg_latency_ms, avg_cpu, ram_used


def get_per_class_recall(model, X_test, y_test):
    """Return recall for each class as a percentage."""
    y_pred = model.predict(X_test)
    recall_values = recall_score(y_test, y_pred, average=None, zero_division=0)
    classes = sorted(list(set(y_test)))

    return {cls: val * 100 for cls, val in zip(classes, recall_values)}


def get_model_size(file_path: Path):
    """Return model file size in MB, or None if it is missing."""
    if file_path.exists():
        return file_path.stat().st_size / (1024 * 1024)
    return None


def print_runtime_table(title, model, X_test, y_test, model_file: Path):
    """Print latency, CPU, RAM, model size, and per-class recall."""
    latency, cpu_usage, ram_usage = measure_performance(model, X_test)
    recall_by_class = get_per_class_recall(model, X_test, y_test)
    model_size = get_model_size(model_file)

    print(f"\n===== {title} =====")
    print(f"{'Metric':<25}{'Value'}")
    print(f"{'-' * 40}")
    print(f"{'Average Latency (ms)':<25}{latency:.2f}")
    print(f"{'CPU Usage (%)':<25}{cpu_usage:.2f}")
    print(f"{'RAM Usage (MB)':<25}{ram_usage:.2f}")
    print(f"{'Model Size (MB)':<25}{model_size if model_size else 'File not found'}")

    for cls, val in recall_by_class.items():
        print(f"Recall ({cls}):{'':<15}{val:.2f}%")


# -----------------------------
# Plots
# -----------------------------

def plot_confusion_matrices(
    binary_model,
    multi_model,
    X_test,
    y_bin_test,
    X_test_multi,
    y_multi_test_filtered,
    multi_classes,
    output_dir: Path,
):
    """Save binary and multi-class confusion matrix plots."""
    y_bin_pred = binary_model.predict(X_test)
    cm_bin = confusion_matrix(y_bin_test, y_bin_pred)
    disp_bin = ConfusionMatrixDisplay(cm_bin, display_labels=["Normal", "Attack"])

    plt.figure(figsize=(7, 6))
    disp_bin.plot(cmap=plt.cm.Blues)
    plt.title("Binary Classification Confusion Matrix")
    plt.tight_layout()
    plt.savefig(output_dir / "binary_confusion_matrix.png", dpi=300)
    plt.close()

    y_multi_pred = multi_model.predict(X_test_multi)
    cm_multi = confusion_matrix(y_multi_test_filtered, y_multi_pred, labels=multi_classes)
    disp_multi = ConfusionMatrixDisplay(cm_multi, display_labels=multi_classes)

    fig, ax = plt.subplots(figsize=(12, 10))
    disp_multi.plot(ax=ax, cmap=plt.cm.Oranges, xticks_rotation=90)
    ax.set_title("Multi-Class Classification Confusion Matrix")
    plt.tight_layout()
    plt.savefig(output_dir / "multiclass_confusion_matrix.png", dpi=300)
    plt.close()


def plot_binary_roc(binary_model, X_test, y_test, output_dir: Path):
    """Save ROC curve for the binary classifier."""
    y_probs = binary_model.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, y_probs)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, lw=2, label=f"Binary ROC (AUC = {roc_auc:.2f})")
    plt.plot([0, 1], [0, 1], lw=1, linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Binary Classification ROC")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(output_dir / "binary_roc.png", dpi=300)
    plt.close()

    return roc_auc


def plot_multi_class_roc(multi_model, X_test, y_test, output_dir: Path):
    """Save ROC curves for the top 10 attack classes by AUC."""
    print("\n--- Multi-Class Classification ROC: Top 10 Attack Classes ---")

    exclude_classes = [0, 1, "normal", "httptunnel"]
    attack_classes = [c for c in multi_model.classes_ if c not in exclude_classes]

    y_test_bin_all = label_binarize(y_test, classes=attack_classes)
    y_probs_full = multi_model.predict_proba(X_test)

    attack_indices = [i for i, c in enumerate(multi_model.classes_) if c in attack_classes]
    y_probs_all = y_probs_full[:, attack_indices]

    roc_auc_by_class = {}

    for i, class_label in enumerate(attack_classes):
        fpr, tpr, _ = roc_curve(y_test_bin_all[:, i], y_probs_all[:, i])
        roc_auc_by_class[class_label] = auc(fpr, tpr)

    top_classes = sorted(roc_auc_by_class, key=roc_auc_by_class.get, reverse=True)[:10]
    print("Top 10 attack classes by AUC:", top_classes)

    plt.figure(figsize=(10, 6))

    for class_label in top_classes:
        i = attack_classes.index(class_label)
        fpr, tpr, _ = roc_curve(y_test_bin_all[:, i], y_probs_all[:, i])
        roc_auc = roc_auc_by_class[class_label]
        plt.plot(fpr, tpr, lw=2, label=f"{class_label} (AUC = {roc_auc:.2f})")

    fpr_micro, tpr_micro, _ = roc_curve(y_test_bin_all.ravel(), y_probs_all.ravel())
    roc_auc_micro = auc(fpr_micro, tpr_micro)
    roc_auc_macro = np.mean([roc_auc_by_class[c] for c in top_classes])

    plt.plot(
        fpr_micro,
        tpr_micro,
        lw=2,
        linestyle="--",
        label=f"Micro-average ROC (AUC = {roc_auc_micro:.2f})",
    )
    plt.plot([0, 1], [0, 1], lw=1, linestyle=":")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Multi-Class ROC: Top 10 Attack Classes")
    plt.legend(loc="center left", bbox_to_anchor=(1, 0.5))
    plt.tight_layout()
    plt.savefig(output_dir / "multiclass_roc.png", dpi=300)
    plt.close()

    print(f"Macro-average AUC (top 10 attack classes): {roc_auc_macro:.2f}")
    print(f"Micro-average AUC: {roc_auc_micro:.2f}")

    return roc_auc_macro, roc_auc_micro


# -----------------------------
# Saving
# -----------------------------

def save_artifacts(
    output_dir: Path,
    binary_model,
    multi_model,
    scaler,
    last_encoder,
    X,
    combined_df,
):
    """Save models, metadata, simulation CSV, and feature statistics."""
    models_dir = output_dir / "models"
    results_dir = output_dir / "results"
    models_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    X.to_csv(results_dir / "simulation_test.csv", index=False)

    joblib.dump(binary_model, models_dir / "binary_model.pkl")
    joblib.dump(multi_model, models_dir / "class_model.pkl")
    joblib.dump(scaler, models_dir / "scaler.pkl")

    if last_encoder is not None:
        joblib.dump(last_encoder, models_dir / "labelEncoder.pkl")

    feature_columns = X.columns.tolist()
    joblib.dump(feature_columns, models_dir / "feature_columns.pkl")

    numeric_df = combined_df.select_dtypes(include=[np.number])
    feature_medians = numeric_df.median()
    np.save(models_dir / "feature_medians.npy", feature_medians.values)

    print("Models and supporting artifacts saved successfully.")
    print("Number of numeric columns:", len(numeric_df.columns))
    print("Number of model feature columns:", len(feature_columns))

    return feature_columns


# -----------------------------
# Main
# -----------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Train LINDEF intrusion detection models.")

    parser.add_argument("--nsl-train", required=True, type=Path, help="Path to NSL-KDD training CSV.")
    parser.add_argument("--nsl-test", required=True, type=Path, help="Path to NSL-KDD testing CSV.")
    parser.add_argument("--unsw-train", required=True, type=Path, help="Path to UNSW-NB15 training CSV.")
    parser.add_argument("--unsw-test", required=True, type=Path, help="Path to UNSW-NB15 testing CSV.")
    parser.add_argument("--cic-zip", required=True, type=Path, help="Path to CIC-IDS zip file.")
    parser.add_argument("--output-dir", default=Path("outputs"), type=Path, help="Where to save models/results.")
    parser.add_argument("--cic-extract-dir", default=Path("data/cic_extracted"), type=Path, help="Where to extract CIC files.")

    return parser.parse_args()


def main():
    args = parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    results_dir = args.output_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    print("=== LINDEF Training Pipeline Started ===")

    cic_csv_files = extract_cic_zip(args.cic_zip, args.cic_extract_dir)
    cic_ids_df = load_cic_ids(cic_csv_files)

    combined_df, X, y_binary, y_multi, encoders, last_encoder = prepare_dataset(
        nsl_train_path=args.nsl_train,
        nsl_test_path=args.nsl_test,
        unsw_train_path=args.unsw_train,
        unsw_test_path=args.unsw_test,
        cic_ids_df=cic_ids_df,
    )

    (
        X_train,
        X_test,
        y_bin_train,
        y_bin_test,
        y_multi_train,
        y_multi_test,
        scaler,
    ) = split_and_scale_features(X, y_binary, y_multi)

    print("\n=== Training Models ===")
    binary_model, X_train_bin, y_bin_train_bal = train_binary_model(X_train, y_bin_train)

    (
        multi_model,
        X_train_multi,
        y_multi_train_filtered,
        X_train_multi_bal,
        y_multi_train_bal,
    ) = train_multi_class_model(X_train, y_multi_train)

    print("\n=== Evaluating Models ===")
    evaluate_model(binary_model, X_test, y_bin_test, "Binary Classification", binary=True)

    valid_classes = y_multi_train_bal.unique()
    X_test_multi, y_multi_test_filtered = filter_multi_class_test_set(
        X_test,
        y_multi_test,
        valid_classes,
    )

    evaluate_model(
        multi_model,
        X_test_multi,
        y_multi_test_filtered,
        "Multi-Class Classification",
        binary=False,
    )

    feature_columns = save_artifacts(
        output_dir=args.output_dir,
        binary_model=binary_model,
        multi_model=multi_model,
        scaler=scaler,
        last_encoder=last_encoder,
        X=X,
        combined_df=combined_df,
    )

    models_dir = args.output_dir / "models"

    print_runtime_table(
        "Binary Model Performance",
        binary_model,
        X_test,
        y_bin_test,
        models_dir / "binary_model.pkl",
    )

    print_runtime_table(
        "Multi-Class Model Performance",
        multi_model,
        X_test_multi,
        y_multi_test_filtered,
        models_dir / "class_model.pkl",
    )

    plot_confusion_matrices(
        binary_model=binary_model,
        multi_model=multi_model,
        X_test=X_test,
        y_bin_test=y_bin_test,
        X_test_multi=X_test_multi,
        y_multi_test_filtered=y_multi_test_filtered,
        multi_classes=np.unique(y_multi_train_filtered),
        output_dir=results_dir,
    )

    plot_binary_roc(binary_model, X_test, y_bin_test, results_dir)
    plot_multi_class_roc(multi_model, X_test_multi, y_multi_test_filtered, results_dir)

    print("\nFeature columns:")
    print(feature_columns)

    print("\n=== LINDEF Training Pipeline Finished ===")
    print(f"Saved outputs to: {args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
