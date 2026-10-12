"""Optional Aletheia structural LSB steganalysis integration."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


DETECTORS = ("spa", "rs")
_NUMBER = re.compile(r"[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?")


def _aletheia_command() -> list[str] | None:
	"""Resolve the configured Aletheia executable or Python script."""
	configured = os.getenv("ALETHEIA_PATH")
	if not configured:
		return None
	path = Path(configured).expanduser()
	if path.is_dir():
		for candidate in (path / "aletheia.py", path / "aletheia"):
			if candidate.exists():
				path = candidate
				break
	if path.suffix == ".py":
		return [sys.executable, str(path)]
	return [str(path)]


def _score(output: str) -> float | None:
	"""Extract the last numeric value from a detector's output."""
	numbers = _NUMBER.findall(output)
	return float(numbers[-1]) if numbers else None


def run_aletheia(image_path: str | Path) -> dict[str, Any]:
	"""Run Aletheia SPA and RS detectors without raising on tool failures."""
	command = _aletheia_command()
	if command is None:
		return {
			"configured": False,
			"status": "not configured",
			"detectors": {detector: {"score": None, "raw": ""} for detector in DETECTORS},
		}
	result: dict[str, Any] = {"configured": True, "status": "ok", "detectors": {}}
	for detector in DETECTORS:
		try:
			completed = subprocess.run(
				command + [detector, str(image_path)],
				capture_output=True,
				text=True,
				check=False,
				timeout=120,
			)
			raw = (completed.stdout + "\n" + completed.stderr).strip()
			result["detectors"][detector] = {
				"score": _score(raw),
				"raw": raw,
				"returncode": completed.returncode,
			}
			if completed.returncode != 0:
				result["status"] = "partial failure"
		except (OSError, subprocess.SubprocessError) as error:
			result["detectors"][detector] = {"score": None, "raw": str(error)}
			result["status"] = "partial failure"
	return result
