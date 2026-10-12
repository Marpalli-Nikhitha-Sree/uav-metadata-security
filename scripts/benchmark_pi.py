"""Benchmark pipeline stages on a Raspberry Pi or laptop."""

from __future__ import annotations

import argparse
import csv
import platform
import socket
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
	sys.path.insert(0, str(ROOT))

from uavsec.keys import derive_keys  # noqa: E402
from uavsec.pipeline import decode, encode  # noqa: E402


RESOLUTIONS = {
	"720p": (1280, 720),
	"1080p": (1920, 1080),
	"4K": (3840, 2160),
}


def _cover(width: int, height: int) -> np.ndarray:
	"""Create a smooth RGB workload with useful RDH capacity."""
	columns = np.arange(width, dtype=np.uint16) % 256
	rows = np.arange(height, dtype=np.uint16)[:, None] % 256
	channel = ((columns[None, :] + rows) % 256).astype(np.uint8)
	return np.stack((channel, np.roll(channel, 17, axis=1), np.roll(channel, 31, axis=1)), axis=-1)


def benchmark_resolution(name: str, size: tuple[int, int], runs: int, output_dir: Path) -> list[dict[str, Any]]:
	"""Measure one resolution for the requested number of runs."""
	output_dir.mkdir(parents=True, exist_ok=True)
	width, height = size
	cover = _cover(width, height)
	source = output_dir / f"benchmark-{name}.png"
	Image.fromarray(cover).save(source)
	keys = derive_keys(bytes(range(32)), f"benchmark-{name}")
	rows: list[dict[str, Any]] = []
	for run in range(runs):
		stego_path = output_dir / f"benchmark-{name}-{run}.png"
		tracemalloc.start()
		started = time.perf_counter()
		encoded = encode(source, keys, f"benchmark-{name}", out_path=stego_path)
		encode_total = (time.perf_counter() - started) * 1000
		decode_started = time.perf_counter()
		decode_result = decode(stego_path, keys, f"benchmark-{name}")
		decode_total = (time.perf_counter() - decode_started) * 1000
		_, peak = tracemalloc.get_traced_memory()
		tracemalloc.stop()
		for entry in encoded.trace:
			rows.append(
				{
					"hostname": socket.gethostname(),
					"cpu_model": platform.processor() or platform.machine(),
					"resolution": name,
					"width": width,
					"height": height,
					"run": run,
					"direction": "encode",
					"stage": entry["stage"],
					"duration_ms": entry["duration_ms"],
					"total_ms": encode_total,
					"peak_memory_bytes": peak,
				}
			)
		for entry in decode_result.trace:
			rows.append(
				{
					"hostname": socket.gethostname(),
					"cpu_model": platform.processor() or platform.machine(),
					"resolution": name,
					"width": width,
					"height": height,
					"run": run,
					"direction": "decode",
					"stage": entry["stage"],
					"duration_ms": entry["duration_ms"],
					"total_ms": decode_total,
					"peak_memory_bytes": peak,
				}
			)
	return rows


def write_benchmark(rows: list[dict[str, Any]], output_root: Path) -> Path:
	"""Write benchmark CSV and a mean stage-duration chart."""
	eval_dir = output_root / "eval"
	eval_dir.mkdir(parents=True, exist_ok=True)
	hostname = socket.gethostname()
	csv_path = eval_dir / f"benchmark_{hostname}.csv"
	fields = list(rows[0]) if rows else ["hostname", "cpu_model", "resolution", "stage", "duration_ms"]
	with csv_path.open("w", newline="", encoding="utf-8") as handle:
		writer = csv.DictWriter(handle, fieldnames=fields)
		writer.writeheader()
		writer.writerows(rows)
	if rows:
		groups: dict[tuple[str, str], list[float]] = {}
		for row in rows:
			key = (str(row["direction"]), str(row["stage"]))
			groups.setdefault(key, []).append(float(row["duration_ms"]))
		labels = [f"{direction}:{stage}" for direction, stage in groups]
		means = [sum(values) / len(values) for values in groups.values()]
		figure, axis = plt.subplots(figsize=(max(10, len(labels) * 0.45), 5))
		axis.bar(labels, means, color="#075985")
		axis.set_ylabel("mean milliseconds")
		axis.set_title(f"Pipeline stage timing · {hostname}")
		axis.tick_params(axis="x", labelrotation=70)
		figure.tight_layout()
		figure.savefig(eval_dir / f"benchmark_{hostname}.png", dpi=150)
		plt.close(figure)
	return csv_path


def main(argv: list[str] | None = None) -> None:
	"""Run the benchmark at all target resolutions."""
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--runs", type=int, default=1)
	parser.add_argument("--output", type=Path, default=ROOT / "outputs")
	args = parser.parse_args(argv)
	if args.runs < 1:
		raise SystemExit("--runs must be positive")
	work_dir = args.output / "eval" / "benchmark_artifacts"
	work_dir.mkdir(parents=True, exist_ok=True)
	rows: list[dict[str, Any]] = []
	for name, size in RESOLUTIONS.items():
		rows.extend(benchmark_resolution(name, size, args.runs, work_dir))
	print(write_benchmark(rows, args.output))


if __name__ == "__main__":
	main()
