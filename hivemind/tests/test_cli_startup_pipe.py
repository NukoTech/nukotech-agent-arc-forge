"""A supervising launcher must see readiness before the server exits."""

import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading


def test_app_reports_readiness_to_a_pipe_while_still_running(tmp_path):
    environment = dict(os.environ)
    environment.pop("PYTHONUNBUFFERED", None)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    command = [sys.executable, "-m", "hive_protocol.product.cli"]
    vault = str(tmp_path / "hive")
    subprocess.run(
        [*command, "init", "--vault", vault],
        env=environment, capture_output=True, check=True, timeout=15,
    )
    process = subprocess.Popen(
        [*command, "app", "--vault", vault, "--port", "0"],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
    try:
        result = json.loads(lines.get(timeout=10))
        assert result["outcome"] == "RUNNING"
        assert result["url"].startswith("http://127.0.0.1:")
        assert process.poll() is None
    finally:
        process.terminate()
        process.communicate(timeout=10)
