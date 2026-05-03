"""
Standalone launcher for the llm-injection-detector web GUI.

This module is the install target for the ``llm-injection-detector-gui``
console script when the package is installed via ``py-modules``.  It delegates
all logic to ``src/llm_injection_detector/gui.py``.
"""

import sys
import pathlib

# When installed as a py-module, the src/ package is not on the path by default.
sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))

from llm_injection_detector.gui import create_app, main  # noqa: E402


def launch_gui(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Launch the Flask web GUI for the LLM Injection Detector."""
    app = create_app()
    print(f"LLM Injection Detector GUI → http://{host}:{port}/")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
