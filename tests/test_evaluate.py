"""Tests for generated dataset evaluation artifacts."""

from pathlib import Path
import csv

import numpy as np
from PIL import Image

from scripts.evaluate import COLUMNS, evaluate_image, write_evaluation


def test_evaluation_writes_complete_artifacts(tmp_path: Path) -> None:
	"""Three generated covers produce rows, summary, and all figures."""
	dataset = tmp_path / "synthetic"
	artifacts = tmp_path / "outputs" / "eval" / "artifacts"
	dataset.mkdir()
	for index in range(3):
		cover = np.tile(np.arange(128, dtype=np.uint8), (128, 1))
		cover = np.roll(cover, index * 3, axis=1)
		Image.fromarray(cover).save(dataset / f"sample-{index}.png")

	rows = [
		evaluate_image(path, bytes(range(32)), artifacts)
		for path in sorted(dataset.glob("*.png"))
	]
	write_evaluation(rows, tmp_path / "outputs")
	results = tmp_path / "outputs" / "eval" / "results.csv"

	assert results.exists()
	with results.open(newline="", encoding="utf-8") as handle:
		rows = list(csv.DictReader(handle))
	assert len(rows) == 3
	assert set(COLUMNS).issubset(rows[0])
	for filename in (
		"psnr_distribution.png",
		"ssim_distribution.png",
		"timing_bars.png",
		"capacity_vs_payload.png",
		"tamper_detection_rate.png",
		"proposed_vs_lsb.png",
	):
		assert (tmp_path / "outputs" / "eval" / filename).exists()
	assert (tmp_path / "outputs" / "eval" / "summary.md").exists()