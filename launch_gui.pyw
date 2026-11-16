"""Double-click (or desktop shortcut) launcher for the CAS Cortex desktop app."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

from cortex.gui import main  # noqa: E402

main()
