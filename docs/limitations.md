# Limitations

LINDEF shows strong performance in controlled testing, but several limitations should be considered before real-world deployment.

## Dataset Limitations

The model is trained on public intrusion detection datasets. These datasets are useful for benchmarking, but they may not fully represent the traffic patterns of large enterprise networks, cloud environments, or modern production systems.

## Live Feature Extraction Limits

CICFlowMeter can extract many flow-based features, but it does not directly recreate every NSL-KDD or UNSW-NB15 feature from raw packet captures. Because LINDEF was trained on a combined feature space, the live dashboard aligns CICFlowMeter output to the saved training feature list and fills missing features with medians or zeros. This allows the system to run, but it may reduce live accuracy if many important features are missing.

## Zero-Day and Adaptive Attacks

Like most supervised machine learning systems, LINDEF may struggle with zero-day attacks or attacks that look very different from the training data. Attackers may also craft traffic to evade detection or exploit weaknesses in the learned model.

## Hardware and Network Scale

Testing was performed in a limited hardware environment. Latency, CPU usage, and RAM usage may change on different machines or in high-bandwidth networks with heavier traffic loads.

## Class Imbalance

Some attack classes have fewer samples than others. SMOTE helps reduce imbalance, but synthetic samples do not perfectly replace real-world examples of rare attacks.

## Model Interpretability

Random Forest models are more interpretable than some deep learning models, but LINDEF is still not as transparent as a manually written rule-based IDS. Additional explainability tools would help users understand why specific flows were flagged.

## Benchmark Comparison Limits

The benchmark comparison includes literature-based ranges for alternative IDS methods. These comparisons are useful for context, but they are not a perfect substitute for testing every system on the exact same hardware, traffic, and evaluation pipeline.
