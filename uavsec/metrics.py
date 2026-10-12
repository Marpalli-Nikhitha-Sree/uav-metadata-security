"""Image quality and embedding metrics."""

from __future__ import annotations

import numpy as np


def _skimage_metrics() -> tuple[object, object]:
	"""Load scikit-image metric functions lazily."""
	try:
		from skimage.metrics import peak_signal_noise_ratio, structural_similarity
	except ImportError as error:
		raise RuntimeError("scikit-image is required for image quality metrics") from error
	return peak_signal_noise_ratio, structural_similarity


def psnr(reference: np.ndarray, candidate: np.ndarray) -> float:
	"""Return PSNR in decibels, or infinity for identical images."""
	if np.array_equal(reference, candidate):
		return float("inf")
	peak_signal_noise_ratio, _ = _skimage_metrics()
	return float(peak_signal_noise_ratio(reference, candidate, data_range=255))


def ssim(reference: np.ndarray, candidate: np.ndarray) -> float:
	"""Return structural similarity with the correct grayscale/RGB axis."""
	if np.array_equal(reference, candidate):
		return 1.0
	_, structural_similarity = _skimage_metrics()
	channel_axis = -1 if reference.ndim == 3 else None
	return float(
		structural_similarity(
			reference,
			candidate,
			data_range=255,
			channel_axis=channel_axis,
		)
	)


def embedding_rate(payload_bits: int | np.ndarray | bytes, cover: np.ndarray) -> float:
	"""Return embedded payload bits per spatial pixel."""
	if isinstance(payload_bits, int):
		bit_count = payload_bits
	elif isinstance(payload_bits, bytes):
		bit_count = len(payload_bits) * 8
	else:
		bit_count = int(np.asarray(payload_bits).size)
	if bit_count < 0 or cover.ndim < 2 or cover.shape[0] * cover.shape[1] == 0:
		raise ValueError("Payload size and cover dimensions must be valid")
	return bit_count / float(cover.shape[0] * cover.shape[1])


def bit_exact(reference: np.ndarray, candidate: np.ndarray) -> bool:
	"""Return whether two covers have identical shape and pixel values."""
	return bool(np.array_equal(reference, candidate))
