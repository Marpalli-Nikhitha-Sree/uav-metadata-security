"""Tests for image quality and embedding metrics."""

import numpy as np

from uavsec.metrics import bit_exact, embedding_rate, psnr, ssim


def test_identical_metrics_and_embedding_rate() -> None:
	"""Identical images have perfect metrics and rates use spatial pixels."""
	image = np.zeros((4, 5, 3), dtype=np.uint8)

	assert psnr(image, image.copy()) == float("inf")
	assert ssim(image, image.copy()) == 1.0
	assert embedding_rate(20, image) == 1.0
	assert bit_exact(image, image.copy())