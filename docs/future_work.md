# Future Work

Future improvements to LINDEF should focus on making the system more reliable, scalable, and deployment-ready.

## Improve Live Feature Extraction

A major next step is improving the live feature extraction pipeline. Future versions should make the CICFlowMeter or NFStream process more stable and ensure that live traffic features match the training feature space as closely as possible.

## Test on Larger Networks

LINDEF should be tested in higher-bandwidth environments, larger enterprise networks, and cloud-based network settings. This would show whether the system can maintain low latency and low memory usage under heavier traffic.

## Expand Training Data

Future training should include newer network intrusion datasets and more real enterprise traffic when available. This would improve generalization and help the model detect modern attack patterns.

## Add Ensemble Models

Future versions could test ensemble approaches, such as combining Random Forest with XGBoost, LightGBM, or anomaly detection models. This may improve performance on rare or difficult attack classes.

## Improve Threshold Tuning

The binary classifier should be tested with adaptive probability thresholds. This could help reduce false positives while still maintaining strong attack detection.

## Add Explainability

Feature importance, SHAP values, or other explainability methods could be added to show why the model classified a flow as suspicious. This would make LINDEF more useful for analysts and judges reviewing detection decisions.

## Improve Containment Logic

The current dashboard maps attack classes to simple responses such as `BLOCK_IP`, `THROTTLE_IP`, and `ISOLATE_HOST`. Future work should create more detailed containment rules based on attack type, confidence score, severity, and repeated behavior over time.

## Add Deployment Support

Future versions should include Docker support, better setup scripts, and clearer installation instructions so LINDEF can be deployed and tested more easily on different machines.

## Compare Against Tools Directly

Instead of relying only on literature-based benchmark ranges, future work should directly run LINDEF, Snort, Suricata, Zeek, and cloud endpoint tools on the same traffic samples and hardware.
