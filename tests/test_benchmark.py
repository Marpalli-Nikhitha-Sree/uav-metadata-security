"""Tests for benchmark output generation."""

from pathlib import Path

from scripts.benchmark_pi import benchmark_resolution, write_benchmark


def test_benchmark_writes_csv_and_chart(tmp_path: Path) -> None:
	"""A small benchmark workload records stage rows and a chart."""
	rows = benchmark_resolution("test", (128, 128), 1, tmp_path / "artifacts")
	path = write_benchmark(rows, tmp_path / "outputs")

	assert rows
	assert path.exists()
	assert (tmp_path / "outputs" / "eval" / f"benchmark_{path.stem.removeprefix('benchmark_')}.png").exists()