# LINDEF: Lightweight Real-Time Network Intrusion Detection and Containment Framework

LINDEF is a machine learning-based network intrusion detection framework designed to identify malicious network traffic while remaining lightweight enough for small businesses, schools, and organizations with limited cybersecurity resources. The system uses a two-stage detection pipeline: a binary classifier first determines whether traffic is benign or malicious, and an attack classification model then identifies the likely attack type.

## Project Goal

The goal of LINDEF is to develop an autonomous intrusion detection framework that is fast, lightweight, accessible, dynamic, and accurate. The system is designed to detect and classify network intrusion incidents without heavily affecting normal system performance.

## Why This Project Matters

Many organizations cannot afford expensive enterprise-level intrusion detection tools or cloud security platforms. As a result, they may be more vulnerable to attacks that can cause data loss, financial damage, operational disruption, and privacy risks. LINDEF explores whether a lightweight machine learning system can provide strong detection performance while using fewer resources than many traditional solutions.

## How LINDEF Works

LINDEF follows a two-stage classification process:

1. **Binary Classification Model**
   - Classifies each network flow as either normal or attack traffic.
   - This acts as the first detection layer.

2. **Attack Classification Model**
   - Runs after suspicious traffic is detected.
   - Predicts the likely attack type so the system can recommend an appropriate response.

The live detection pipeline is designed to capture traffic, extract flow features using CICFlowMeter, align the extracted features to the training feature list, scale the data, and classify the traffic using the trained models.

## Datasets Used

LINDEF combines multiple public intrusion detection datasets to improve attack coverage and reduce overfitting to one dataset format.

| Dataset | Description |
|---|---|
| NSL-KDD | Benchmark intrusion detection dataset with normal traffic and multiple attack categories. |
| UNSW-NB15 | Modern intrusion detection dataset with normal traffic and multiple attack categories. |
| CIC-IDS | Flow-based intrusion detection dataset with benign traffic and multiple attack types. |

Combining these datasets provides broader attack coverage, a larger training set, and a more diverse feature space.

## Model Training

The training pipeline includes:

- Loading NSL-KDD, UNSW-NB15, and CIC-IDS data
- Cleaning missing, infinite, and duplicate values
- Removing leakage-prone columns such as IP addresses, timestamps, and flow identifiers
- Creating binary and multi-class labels
- Encoding categorical features
- Scaling features with `StandardScaler`
- Applying SMOTE to reduce class imbalance
- Training Random Forest classifiers
- Saving model artifacts for inference and dashboard use

## Results

LINDEF produced strong results in both binary detection and attack classification.

| Model | Accuracy | Precision | Recall | F1-score |
|---|---:|---:|---:|---:|
| Binary Classification Model | 0.9983 | 0.9983 | 0.9983 | 0.9983 |
| Attack Classification Model | 0.9415 | 0.9416 | 0.9415 | 0.9415 |

Additional reported performance metrics:

| Metric | Binary Model | Attack Classification Model |
|---|---:|---:|
| False Positive Rate | 0.21% | 0.37% |
| Average Latency | 54.18 ms | 53.79 ms |
| RAM Usage | 18.52 MB | 8.32 MB |
| ROC-AUC | 0.97 | 0.89 |

## Benchmark Comparison

LINDEF was compared against common intrusion detection approaches, including signature-based IDS, anomaly-based IDS, cloud-based endpoint detection, and rule-based IDS. The benchmark comparison includes project-generated LINDEF results and literature-based ranges for alternative IDS approaches.

| Method | Detection Accuracy | False Positive Rate | Average Latency | RAM Usage |
|---|---:|---:|---:|---:|
| LINDEF Binary Model | 99.83% | 0.21% | 54.18 ms | 18.52 MB |
| LINDEF Attack Classification Model | 94.15% | 0.37% | 53.79 ms | 8.32 MB |
| Signature-Based IDS | 94%–98% | <1% | <5 ms | 50–200 MB |
| Anomaly-Based IDS | 85%–95% | 3%–5% | 10–50 ms | 1–4 GB |
| Cloud-Based Endpoint Detection | 96%–99% | 2% | 50–200 ms | Varies |
| Rule-Based IDS | 90%–95% | 1%–2% | 5–15 ms | 200–500 MB |

While LINDEF has slightly higher latency than some traditional IDS approaches, it provides strong accuracy, low false positive rates, and low RAM usage. The latency tradeoff is acceptable for the intended use case of lightweight monitoring in smaller or moderate-traffic environments.

## Live Dashboard

The project includes a Streamlit dashboard for simulation and live detection testing.

The dashboard can:

- Load trained LINDEF models
- Process simulation CSV data
- Support live traffic processing through TShark and CICFlowMeter
- Align extracted features to the trained feature list
- Classify traffic as benign or malicious
- Predict attack type
- Display severity and recommended response actions
- Log recent detections
- Visualize attack vs. benign traffic and severity distribution

Example response actions include:

| Attack Type | Example Response |
|---|---|
| DoS-style attacks | `BLOCK_IP` |
| Scanning/probe attacks | `BLOCK_IP` |
| Credential/access attempts | `THROTTLE_IP` |
| Tunneling or host compromise attacks | `ISOLATE_HOST` |
| Normal traffic | `ALLOW` |

## Repository Structure

```text
LINDEF/
├── README.md
├── requirements.txt
├── .gitignore
│
├── src/
│   └── train_lindef_models.py
│
├── notebooks/
│   └── LINDEF_training_colab.ipynb
│
├── app/
│   └── dashboard.py
│
├── data/
│   └── README.md
│   └── LINDEF_Simulation_Dashboard.mp4
│
├── models/
│   └── README.md
│
├── results/
│   ├── README.md
│   ├── benchmark_results.csv
│   ├── benchmark_results.md
│   ├── confusion_matrices.png
│   ├── binary_roc.png
│   └── multiclass_roc.png
│
└── docs/
    ├── methodology.md
    ├── limitations.md
    └── future_work.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/LINDEF.git
cd LINDEF
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Training the Models

The easiest way to train the models is to run the Colab notebook:

```text
notebooks/LINDEF_training_colab.ipynb
```

The notebook generates the following artifacts:

```text
binary_model.pkl
class_model.pkl
scaler.pkl
feature_columns.pkl
feature_medians.npy
labelEncoder.pkl
simulation_test.csv
confusion_matrices.png
binary_roc.png
multiclass_roc.png
```

Model artifacts are not included in this repository by default because some files may be too large for normal GitHub upload. To use the dashboard locally, place the generated model files inside the `models/` folder.

## Running the Dashboard

After training the models and placing the artifacts in `models/`, run:

```bash
streamlit run app/dashboard.py
```

Expected local model files:

```text
models/binary_model.pkl
models/class_model.pkl
models/scaler.pkl
models/feature_columns.pkl
models/feature_medians.npy
```

## Limitations

- Public datasets may not fully represent real-world enterprise traffic.
- CICFlowMeter does not directly recreate every NSL-KDD or UNSW-NB15 feature from raw packet captures.
- Live performance depends on feature extraction quality.
- Some attack classes have fewer samples than others.
- The system may struggle with zero-day attacks that differ significantly from the training data.
- Benchmark comparisons for non-LINDEF systems are literature-based ranges, not all direct same-hardware tests.

## Future Work

- Improve live feature extraction consistency.
- Test LINDEF on larger and higher-bandwidth networks.
- Add ensemble models for stronger classification.
- Tune thresholds to reduce false positives.
- Add explainability tools such as feature importance or SHAP.
- Expand containment logic by attack type and confidence score.
- Add Docker support for easier deployment.
- Directly benchmark LINDEF against Snort, Suricata, Zeek, and endpoint detection tools on the same hardware.

## Tools and Libraries

LINDEF uses:

- Python
- pandas
- NumPy
- scikit-learn
- imbalanced-learn
- Matplotlib
- Seaborn
- Joblib
- psutil
- Streamlit
- CICFlowMeter
- TShark/Wireshark

## Project Status

LINDEF is a research and prototype system. It demonstrates that a lightweight machine learning approach can achieve strong intrusion detection performance while maintaining low memory usage. Further testing is needed before deployment in high-bandwidth or enterprise environments.

## Author

Sanjay Balaji
