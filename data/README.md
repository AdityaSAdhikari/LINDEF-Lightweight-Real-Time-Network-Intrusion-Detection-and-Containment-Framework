# Data

This project uses public intrusion detection datasets. The full datasets are not included in this repository because of file size and licensing constraints.

## Required files

The training pipeline expects:

- NSL-KDD(training) - KDDTrain+.csv
- NSL-KDD(testing) - KDDTest+.csv
- UNSW-NB15 (training) - UNSW_NB15_training-set (1).csv
- UNSW-NB15 (testing) - UNSW_NB15_testing-set (1).csv
- CIC-IDS CSV files or a CIC-IDS zip file

## Notes

During preprocessing, the datasets are combined, cleaned, sampled, and standardized. Columns that could cause leakage, such as IP addresses, flow IDs, and timestamps, are removed before training.
