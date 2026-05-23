# Models

Model artifacts are generated after running the training pipeline.

Expected outputs:

- `binary_model.pkl` — binary normal vs. attack classifier
- `class_model.pkl` — multi-class attack type classifier
- `scaler.pkl` — fitted StandardScaler
- `feature_columns.pkl` — ordered feature list used during inference
- `feature_medians.npy` — median feature values
- `labelEncoder.pkl` — label encoder artifact from the original workflow

The model files are not included by default because they may be large.
