"""Evaluate reversible UAV metadata protection over an image dataset."""

from __future__ import annotations

import argparse
import csv
import io
import sys
import time
from pathlib import Path
from typing import Any, Iterable

import matplotlib.pyplot as plt
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
	sys.path.insert(0, str(ROOT))

from uavsec.cover import load_png, save_stripped_png  # noqa: E402
from uavsec.keys import derive_keys, load_master_key  # noqa: E402
from uavsec.metrics import bit_exact, embedding_rate, psnr, ssim  # noqa: E402
from uavsec.pipeline import decode, encode  # noqa: E402
from uavsec.shuffler import bytes_to_bits  # noqa: E402
from uavsec.steganalysis import run_aletheia  # noqa: E402


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}
ATTACKS = ("pixel_flip", "jpeg", "crop_pad", "noise")
COLUMNS = [
	"dataset", "image", "psnr", "ssim", "bpp", "capacity_bits", "payload_bytes",
	"encode_ms", "decode_ms", "bit_exact", "metadata_recovery", "verdict",
	"tamper_pixel_flip", "tamper_jpeg", "tamper_crop_pad", "tamper_noise",
	"aletheia_cover_spa", "aletheia_stego_spa", "aletheia_cover_rs", "aletheia_stego_rs",
	"baseline_psnr", "baseline_spa", "baseline_rs",
]


def _images(dataset: Path, limit: int | None) -> list[Path]:
	"""Find supported images recursively in deterministic order."""
	paths = sorted(path for path in dataset.rglob("*") if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS)
	return paths[:limit] if limit is not None else paths


def _attack(image: np.ndarray, attack_type: str) -> np.ndarray:
	"""Apply one deterministic tamper transform while preserving dimensions."""
	values = np.asarray(image).copy()
	if values.ndim == 2:
		values = values[..., None]
	if attack_type == "pixel_flip":
		values[values.shape[0] // 2, values.shape[1] // 2, 0] ^= 1
	elif attack_type == "jpeg":
		buffer = io.BytesIO()
		Image.fromarray(values.squeeze() if values.shape[2] == 1 else values).save(buffer, format="JPEG", quality=45)
		decoded = np.array(Image.open(io.BytesIO(buffer.getvalue())).convert("RGB"))
		values = decoded if values.shape[2] == 3 else decoded[..., :1]
	elif attack_type == "crop_pad":
		cropped = values[1:-1, 1:-1]
		padded = np.zeros_like(values)
		padded[1:-1, 1:-1] = cropped[: values.shape[0] - 2, : values.shape[1] - 2]
		values = padded
	elif attack_type == "noise":
		noise = np.random.default_rng(7).integers(-3, 4, values.shape)
		values = np.clip(values.astype(np.int16) + noise, 0, 255).astype(np.uint8)
	else:
		raise ValueError(f"Unknown attack type: {attack_type}")
	return values[..., 0] if image.ndim == 2 else values


def lsb_baseline(cover: np.ndarray, payload_bits: np.ndarray) -> np.ndarray:
	"""Replace least-significant pixel bits with the same payload."""
	values = np.asarray(cover, dtype=np.uint8).copy().reshape(-1)
	bits = np.asarray(payload_bits, dtype=np.uint8).reshape(-1)
	count = min(values.size, bits.size)
	values[:count] = (values[:count] & 0xFE) | bits[:count]
	return values.reshape(cover.shape)


def _aletheia_scores(result: dict[str, Any], detector: str) -> Any:
	"""Get one detector score or a clear unavailable marker."""
	if not result.get("configured"):
		return "not configured"
	return result.get("detectors", {}).get(detector, {}).get("score") or "unavailable"


def _safe_metric(function: Any, *args: Any) -> float:
	"""Return a finite metric value for CSV output."""
	try:
		value = float(function(*args))
		return value if np.isfinite(value) else 0.0
	except Exception:
		return 0.0


def evaluate_image(path: Path, keys: Any, output_dir: Path) -> dict[str, Any]:
	"""Evaluate one image and return a complete CSV row."""
	output_dir.mkdir(parents=True, exist_ok=True)
	row: dict[str, Any] = {column: 0 for column in COLUMNS}
	row.update({"dataset": path.parent.name, "image": str(path), "verdict": "ERROR"})
	try:
		cover = load_png(path)
		mission_id = f"evaluation-{path.stem}"
		if isinstance(keys, bytes):
			keys = derive_keys(keys, mission_id)
		stego_path = output_dir / f"{path.stem}-stego.png"
		started = time.perf_counter()
		encoded = encode(path, keys, mission_id, out_path=stego_path)
		encode_ms = (time.perf_counter() - started) * 1000
		stego = load_png(stego_path)
		started = time.perf_counter()
		decoded = decode(stego_path, keys, mission_id)
		decode_ms = (time.perf_counter() - started) * 1000
		payload_bits = bytes_to_bits(encoded.payload_bytes)
		cover_analysis = run_aletheia(path)
		stego_analysis = run_aletheia(stego_path)
		row.update(
			{
				"dataset": path.parent.name,
				"image": str(path),
				"psnr": _safe_metric(psnr, cover, stego),
				"ssim": _safe_metric(ssim, cover, stego),
				"bpp": embedding_rate(payload_bits, cover),
				"capacity_bits": encoded.capacity_bits,
				"payload_bytes": len(encoded.payload_bytes),
				"encode_ms": encode_ms,
				"decode_ms": decode_ms,
				"bit_exact": bit_exact(cover, decoded.restored_image) if decoded.restored_image is not None else False,
				"metadata_recovery": decoded.metadata == encoded.metadata,
				"verdict": decoded.verdict,
				"aletheia_cover_spa": _aletheia_scores(cover_analysis, "spa"),
				"aletheia_stego_spa": _aletheia_scores(stego_analysis, "spa"),
				"aletheia_cover_rs": _aletheia_scores(cover_analysis, "rs"),
				"aletheia_stego_rs": _aletheia_scores(stego_analysis, "rs"),
			}
		)
		baseline = lsb_baseline(cover, payload_bits)
		baseline_path = output_dir / f"{path.stem}-lsb.png"
		save_stripped_png(baseline, baseline_path)
		baseline_analysis = run_aletheia(baseline_path)
		row["baseline_psnr"] = _safe_metric(psnr, cover, baseline)
		row["baseline_spa"] = _aletheia_scores(baseline_analysis, "spa")
		row["baseline_rs"] = _aletheia_scores(baseline_analysis, "rs")
		for attack_type in ATTACKS:
			attacked = _attack(stego, attack_type)
			attack_path = output_dir / f"{path.stem}-{attack_type}.png"
			save_stripped_png(attacked, attack_path)
			attack_result = decode(attack_path, keys, mission_id)
			row[f"tamper_{attack_type}"] = attack_result.verdict != "AUTHENTIC"
	except Exception as error:
		row["verdict"] = f"ERROR: {type(error).__name__}"
	return {column: row.get(column, 0) for column in COLUMNS}


def _numeric_values(rows: list[dict[str, Any]], column: str) -> np.ndarray:
	"""Return finite numeric values from a result column."""
	values = []
	for row in rows:
		try:
			value = float(row[column])
			if np.isfinite(value):
				values.append(value)
		except (KeyError, TypeError, ValueError):
			continue
	return np.asarray(values, dtype=float)


def _plot_distributions(rows: list[dict[str, Any]], output_dir: Path) -> None:
	"""Write PSNR and SSIM distribution figures."""
	for metric in ("psnr", "ssim"):
		figure, axis = plt.subplots(figsize=(7, 4))
		axis.hist(_numeric_values(rows, metric), bins=12, color="#075985", alpha=0.85)
		axis.set(title=f"{metric.upper()} distribution", xlabel=metric.upper(), ylabel="images")
		axis.grid(alpha=0.2)
		figure.tight_layout()
		figure.savefig(output_dir / f"{metric}_distribution.png", dpi=150)
		plt.close(figure)


def _write_figures(rows: list[dict[str, Any]], output_dir: Path) -> None:
	"""Write all requested evaluation figures."""
	_plot_distributions(rows, output_dir)
	figure, axis = plt.subplots(figsize=(8, 4))
	means = [_numeric_values(rows, column).mean() for column in ("encode_ms", "decode_ms")]
	axis.bar(["encode_ms", "decode_ms"], means, color=["#075985", "#16805c"])
	axis.set(title="Mean pipeline timing", ylabel="milliseconds")
	figure.tight_layout()
	figure.savefig(output_dir / "timing_bars.png", dpi=150)
	plt.close(figure)
	figure, axis = plt.subplots(figsize=(7, 4))
	axis.scatter(_numeric_values(rows, "payload_bytes"), _numeric_values(rows, "capacity_bits"), c="#075985")
	axis.set(title="Capacity versus payload", xlabel="payload bytes", ylabel="capacity bits")
	axis.grid(alpha=0.2)
	figure.tight_layout()
	figure.savefig(output_dir / "capacity_vs_payload.png", dpi=150)
	plt.close(figure)
	figure, axis = plt.subplots(figsize=(8, 4))
	tamper_columns = [f"tamper_{attack}" for attack in ATTACKS]
	tamper_rates = [sum(bool(row.get(column)) for row in rows) / max(1, len(rows)) for column in tamper_columns]
	axis.bar(ATTACKS, tamper_rates, color="#b97900")
	axis.set(title="Tamper detection rate", ylabel="rate", ylim=(0, 1))
	figure.tight_layout()
	figure.savefig(output_dir / "tamper_detection_rate.png", dpi=150)
	plt.close(figure)
	figure, axes = plt.subplots(1, 2, figsize=(10, 4))
	for axis, metric, baseline in ((axes[0], "PSNR", "baseline_psnr"), (axes[1], "SPA detectability", "baseline_spa")):
		proposed_values = _numeric_values(rows, "psnr" if metric == "PSNR" else "aletheia_stego_spa")
		baseline_values = _numeric_values(rows, baseline)
		proposed = proposed_values.mean() if proposed_values.size else 0
		baseline_value = baseline_values.mean() if baseline_values.size else 0
		axis.bar(["proposed", "LSB"], [proposed, baseline_value], color=["#075985", "#b42318"])
		axis.set_title(metric)
	figure.tight_layout()
	figure.savefig(output_dir / "proposed_vs_lsb.png", dpi=150)
	plt.close(figure)


def write_evaluation(rows: Iterable[dict[str, Any]], output_root: Path) -> list[dict[str, Any]]:
	"""Write results CSV, grouped summary markdown, and figures."""
	eval_dir = output_root / "eval"
	eval_dir.mkdir(parents=True, exist_ok=True)
	result_rows = list(rows)
	with (eval_dir / "results.csv").open("w", newline="", encoding="utf-8") as handle:
		writer = csv.DictWriter(handle, fieldnames=COLUMNS)
		writer.writeheader()
		writer.writerows(result_rows)
	numeric_columns = [column for column in COLUMNS if column not in {"dataset", "image", "verdict"}]
	groups: dict[str, list[dict[str, Any]]] = {}
	for row in result_rows:
		groups.setdefault(str(row.get("dataset", "unknown")), []).append(row)
	lines = ["# Evaluation summary", "", "| Dataset | Metric | Mean | Std |", "|---|---|---:|---:|"]
	for dataset, dataset_rows in sorted(groups.items()):
		for column in numeric_columns:
			values = _numeric_values(dataset_rows, column)
			if values.size:
				lines.append(f"| {dataset} | {column} | {values.mean():.4f} | {values.std():.4f} |")
	(eval_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
	_write_figures(result_rows, eval_dir)
	return result_rows


def main(argv: list[str] | None = None) -> None:
	"""Run dataset evaluation from the command line."""
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("dataset", type=Path)
	parser.add_argument("--limit", type=int, default=None)
	parser.add_argument("--master-key", default=None)
	parser.add_argument("--output", type=Path, default=ROOT / "outputs")
	args = parser.parse_args(argv)
	master_key = bytes.fromhex(args.master_key) if args.master_key else load_master_key()
	image_paths = _images(args.dataset, args.limit)
	if not image_paths:
		raise SystemExit(f"No supported images found in {args.dataset}")
	rows = [evaluate_image(path, master_key, args.output / "eval" / "artifacts") for path in image_paths]
	write_evaluation(rows, args.output)
	print(f"Wrote {len(rows)} rows to {args.output / 'eval' / 'results.csv'}")


if __name__ == "__main__":
	main()
