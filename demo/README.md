# LINDEF Dashboard Demo

This folder contains a screen-recorded demonstration of the LINDEF dashboard.

## Demo Description

The demo shows LINDEF processing sample network-flow data through the dashboard. The system loads the trained models, classifies traffic as benign or malicious, predicts attack types, assigns severity levels, recommends response actions, and displays detection logs and charts.

## Important Note

This demo uses sample flow data generated from the training/testing pipeline. It is a simulation-style dashboard demo, not a fully deployed live network environment.

The dashboard is designed to support a future live workflow using:

- TShark for packet capture
- CICFlowMeter for feature extraction
- LINDEF models for binary and attack-type classification
- Streamlit for visualization

## What the Demo Shows

- Model loading
- Feature-aligned sample flow processing
- Benign vs. attack classification
- Attack type prediction
- Severity assignment
- Recommended response actions
- Recent detection logs
- Dashboard charts

## Demo Video

If the video is included in this repository:

`lindef_dashboard_demo.mp4`

If hosted externally:

[Watch the LINDEF dashboard demo](PASTE-LINK-HERE)
