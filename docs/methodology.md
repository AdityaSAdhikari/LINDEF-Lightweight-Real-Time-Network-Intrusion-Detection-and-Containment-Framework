# Methodology

LINDEF is a lightweight network intrusion detection and containment framework designed to detect malicious network traffic while keeping latency, memory usage, and deployment complexity low. The system uses a two-stage machine learning pipeline: a binary classifier first determines whether a network flow is benign or malicious, and a multi-class classifier then identifies the likely attack type for suspicious traffic.

## 1. Dataset Selection

The training pipeline combines three public intrusion detection datasets:

- **NSL-KDD**: benchmark intrusion detection dataset with normal traffic and multiple attack categories.
- **UNSW-NB15**: modern network intrusion dataset with normal traffic and nine attack categories.
- **CIC-IDS**: flow-based network traffic dataset containing benign traffic and multiple attack types.

Combining these datasets increases attack-type coverage, expands the training sample size, and reduces the risk of overfitting to one dataset format or traffic environment.

## 2. Data Loading and Cleaning

The datasets are loaded and combined into one training DataFrame. Because CIC-IDS files can be large, the pipeline reads CIC-IDS CSV files in chunks to reduce memory pressure.

The preprocessing pipeline performs the following cleaning steps:

- Removes infinite values and replaces invalid entries.
- Drops rows without an attack label.
- Fills remaining missing values.
- Removes duplicate rows.
- Downcasts large numeric columns to reduce RAM usage.
- Removes likely leakage columns such as IP addresses, flow IDs, and timestamps.

Columns such as source IP, destination IP, timestamps, and flow identifiers are removed because they can make the model memorize dataset-specific patterns instead of learning general network behavior.

## 3. Feature Engineering

When CIC-style flow features are available, LINDEF creates an additional packet-rate feature:

`packet_rate = total packets / flow duration`

This feature helps represent how quickly packets move through a flow, which can be useful for detecting high-volume or abnormal traffic patterns.

## 4. Label Creation

LINDEF creates two labels:

- **Binary label**: classifies traffic as normal or attack.
- **Multi-class label**: preserves the specific attack type for attack classification.

Traffic labeled as `NORMAL` or `BENIGN` is treated as normal. All other labels are treated as attacks.

## 5. Categorical Encoding and Feature Alignment

Non-label categorical columns are encoded numerically so they can be used by the machine learning models. The final list of training features is saved as `feature_columns.pkl`. This is important for deployment because live traffic or simulation data must be aligned to the exact same feature order used during training.

For live or dashboard use, incoming flow data is cleaned, matched to `feature_columns.pkl`, and missing columns are filled with saved feature medians or zeros.

## 6. Model Training

LINDEF trains two Random Forest classifiers:

1. **Binary Random Forest model**  
   Detects whether traffic is benign or malicious.

2. **Multi-class Random Forest model**  
   Classifies suspicious traffic by attack type.

SMOTE is applied to reduce class imbalance before training. For the multi-class model, attack classes with too few examples are filtered out before SMOTE to avoid resampling errors.

## 7. Evaluation

The models are evaluated using:

- Accuracy
- Precision
- Recall
- F1-score
- False positive rate
- ROC-AUC
- Average latency
- CPU usage
- RAM usage
- Model size

The binary model focuses on detection performance, while the multi-class model focuses on identifying attack categories after suspicious traffic has been detected.

## 8. Live Detection and Dashboard Pipeline

The Streamlit dashboard supports simulation-based testing and live traffic processing. In the live pipeline, traffic is captured with TShark, converted into flow features using CICFlowMeter, aligned to the trained feature list, scaled with the saved scaler, and passed through the binary and multi-class models.

The dashboard displays recent detections, attack severity, attack probability, and recommended response actions such as allowing traffic, blocking an IP, throttling an IP, or isolating a host.
