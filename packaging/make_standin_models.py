"""
Put stand-in models and a simulation file into a LINDEF-Server folder, so the
simulation can run before the real trained models are available.

    python packaging/make_standin_models.py                  # into dist/LINDEF-Server
    python packaging/make_standin_models.py path/to/folder   # into another server folder

The stand-ins are RandomForest classifiers, like the real ones, trained on
random numbers: the program runs end to end, but the detections are not real
results. Copy the trained model files over them to switch.

The simulation file mimics ordinary traffic: about 95% benign, a trickle of
background scans, and a few attack bursts (a flood or a password-guessing run).

Refuses to touch a folder that already holds model files, unless --replace is given.
"""

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "packet_rate",
            "Flow Bytes/s", "Fwd Packet Length Mean"]
# Attack mix loosely like the training data: mostly DoS and probes, few host compromises.
ATTACKS = {"neptune": 0.40, "smurf": 0.18, "portsweep": 0.10, "nmap": 0.10, "guess_passwd": 0.08,
           "warezmaster": 0.05, "apache2": 0.06, "ftp_write": 0.02, "httptunnel": 0.01}
ATTACK_RATE = 0.18


def main():
    args = [a for a in sys.argv[1:] if a != "--replace"]
    target = Path(args[0]) if args else ROOT / "dist" / "LINDEF-Server"
    models, results = target / "models", target / "results"
    if (models / "binary_model.pkl").exists() and "--replace" not in sys.argv:
        sys.exit(f"{models} already has real model files. Nothing was changed.")
    models.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(42)
    X = rng.random((5000, len(FEATURES)))
    is_attack = (X[:, 4] > 1 - ATTACK_RATE).astype(int)
    names = np.array(list(ATTACKS))
    weights = np.array(list(ATTACKS.values()))
    attack_type = names[np.searchsorted(np.cumsum(weights / weights.sum()), X[:, 5] * 0.9999)]

    scaler = StandardScaler().fit(X)
    scaled = scaler.transform(X)
    joblib.dump(scaler, models / "scaler.pkl")
    joblib.dump(RandomForestClassifier(n_estimators=40, random_state=0).fit(scaled, is_attack),
                models / "binary_model.pkl")
    joblib.dump(RandomForestClassifier(n_estimators=40, random_state=0).fit(scaled, attack_type),
                models / "class_model.pkl")
    joblib.dump(FEATURES, models / "feature_columns.pkl")
    np.save(models / "feature_medians.npy", np.median(X, axis=0))

    # Like the real simulation_test.csv: feature columns only (no addresses), packet_rate derived later.
    # Column 4 decides attack or benign for these models, column 5 the attack type.
    edges = np.concatenate([[0], np.cumsum(weights / weights.sum())]) / 0.9999
    def type_value(name, n):
        i = list(ATTACKS).index(name)
        return edges[i] + (edges[i + 1] - edges[i]) * (0.2 + 0.6 * rng.random(n))

    rows = 6000
    sim = rng.random((rows, len(FEATURES)))
    sim[:, 4] = rng.random(rows) * 0.75                          # ordinary traffic
    scans = np.flatnonzero(rng.random(rows) < 0.005)             # background scans and probes
    sim[scans, 4] = 0.9 + 0.1 * rng.random(len(scans))
    sim[scans, 5] = [type_value(rng.choice(["portsweep", "nmap", "guess_passwd"]), 1)[0] for _ in scans]
    for name, start, length in [("neptune", 700, 140), ("guess_passwd", 2100, 90),
                                ("smurf", 3300, 120), ("warezmaster", 4400, 60), ("httptunnel", 5300, 25)]:
        burst = np.arange(start, start + length)
        burst = burst[rng.random(length) < 0.7]                  # bursts are mixed with normal flows
        sim[burst, 4] = 0.9 + 0.1 * rng.random(len(burst))
        sim[burst, 5] = type_value(name, len(burst))
    pd.DataFrame(sim, columns=FEATURES).drop(columns=["packet_rate"]).to_csv(
        results / "simulation_test.csv", index=False)

    print(f"Stand-in models and simulation file written to {target}")
    print("Restart LINDEF-Server, then press Start in the desktop app or on the phone.")


if __name__ == "__main__":
    main()
