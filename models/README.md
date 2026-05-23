# Models

Model artifacts are generated after running the training notebook.

Expected generated files:

- `binary_model.pkl` — binary normal vs. attack classifier
- `class_model.pkl` — multi-class attack type classifier
- `scaler.pkl` — fitted StandardScaler
- `feature_columns.pkl` — ordered feature list used during inference
- `feature_medians.npy` — median feature values
- `labelEncoder.pkl` — label encoder artifact from the original workflow

These files are not included in this repository because some model artifacts are larger than GitHub's normal browser upload limit.

To generate the model artifacts, run:

`notebooks/LINDEF_training_colab.ipynb`

For local dashboard use, place the generated files in this folder.
