"""
Build LINDEF-Server: the agent as one double-clickable program for the server
being defended. No Python is needed on that server.

    python packaging/build_server.py

Run it on the kind of machine the program is for (PyInstaller cannot cross-build):
  Windows        -> dist/LINDEF-Server/LINDEF-Server.exe
  macOS / Linux  -> dist/LINDEF-Server/LINDEF-Server

Copy the whole dist/LINDEF-Server folder to the server. Model files found in
models/ and results/simulation_test.csv are copied in automatically.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dist" / "LINDEF-Server"
NAME = "LINDEF-Server"

# The agent only needs pandas, numpy, scikit-learn, joblib, segno, and
# cryptography. These come in through other requirements and would bloat the program.
EXCLUDE = ["matplotlib", "seaborn", "imblearn", "streamlit", "webview", "IPython", "tkinter",
           "PyQt5", "PyQt6", "PySide2", "PySide6", "pytest", "altair", "pyarrow"]

# The trained models are RandomForest classifiers and a StandardScaler. joblib
# imports their classes by name when loading, which PyInstaller cannot see.
HIDDEN = ["sklearn.ensemble", "sklearn.tree", "sklearn.preprocessing"]

README = """LINDEF Server
=============

This is the LINDEF agent. Run it on the computer you want LINDEF to protect.

1. Put the trained model files in the "models" folder next to this program:
   binary_model.pkl, class_model.pkl, scaler.pkl, feature_columns.pkl,
   feature_medians.npy
2. For simulation mode, put simulation_test.csv in the "results" folder.
3. Open {program}. A window shows the server's address and a desktop
   pairing code (also as a QR code). Paste that code into the LINDEF desktop
   app. Pair phones from the desktop app afterwards.
4. If the computer asks whether to allow incoming network connections, allow
   them, or the desktop and phone cannot connect.

Leave the window open while LINDEF is running. Close it to stop LINDEF.

Containment is simulated: LINDEF shows what it would block, throttle, or
isolate, but never changes real traffic.

Live capture (optional) needs TShark and CICFlowMeter installed, and is set
when starting the program from a terminal, for example:
  {program} --tshark "C:\\Program Files\\Wireshark\\tshark.exe" --interface 1 --cicflowmeter "CICFlowMeter.bat \\"{{input}}\\" \\"{{output}}\\""
Run {program} --help for every option, including --port and --reset.
"""


def main():
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "pyinstaller"], check=True)
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
        "--name", NAME,
        "--paths", str(ROOT / "app"),
        "--icon", str(ROOT / "app" / "web" / "icon.png"),  # converted to .ico/.icns by Pillow
        "--distpath", str(OUT),
        "--workpath", str(ROOT / "build" / "pyinstaller"),
        "--specpath", str(ROOT / "build"),
        *[f"--exclude-module={m}" for m in EXCLUDE],
        *[f"--hidden-import={m}" for m in HIDDEN],
        str(ROOT / "app" / "agent.py"),
    ]
    subprocess.run(command, check=True)

    program = NAME + (".exe" if sys.platform == "win32" else "")
    (OUT / "models").mkdir(exist_ok=True)
    (OUT / "results").mkdir(exist_ok=True)
    for pattern in ("*.pkl", "*.npy"):
        for model_file in (ROOT / "models").glob(pattern):
            shutil.copy2(model_file, OUT / "models" / model_file.name)
    simulation = ROOT / "results" / "simulation_test.csv"
    if simulation.exists():
        shutil.copy2(simulation, OUT / "results" / simulation.name)
    (OUT / "README.txt").write_text(README.format(program=program))

    models = sorted(p.name for p in (OUT / "models").iterdir())
    print(f"\nBuilt {OUT / program}")
    print("Models included: " + (", ".join(models) if models else "none yet (add them to the models folder)"))


if __name__ == "__main__":
    main()
