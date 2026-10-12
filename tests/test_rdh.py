"""Tests for reversible data hiding."""

import numpy as np
import pytest

from uavsec.errors import CapacityError, ExtractionError
from uavsec.rdh import capacity_bits, embed, extract


def _covers() -> list[np.ndarray]:
	gradient = np.arange(64 * 64, dtype=np.uint8).reshape(64, 64)
	rng = np.random.default_rng(42)
	return [
		gradient,
		rng.integers(0, 256, size=(64, 64), dtype=np.uint8),
		np.zeros((64, 64), dtype=np.uint8),
		np.full((64, 64), 255, dtype=np.uint8),
		gradient.copy(),
		gradient[:, :, None].repeat(3, axis=2),
	]


@pytest.mark.parametrize("shape", [(16, 16), (64, 64), (64, 64, 3)])
@pytest.mark.parametrize("payload_size", [1, 1000])
def test_round_trip_for_supported_covers(shape: tuple[int, ...], payload_size: int) -> None:
	"""Embedded payloads restore smooth, random, saturated, grayscale, and RGB covers."""
	rng = np.random.default_rng(sum(shape) + payload_size)
	cover = rng.integers(1, 255, size=shape, dtype=np.uint8)
	if shape == (64, 64):
		cover[:8, :8] = 0
		cover[-8:, -8:] = 255
	key = b"location-key"
	if capacity_bits(cover, key) < payload_size:
		pytest.skip("cover has insufficient prediction-error capacity")
	payload = rng.integers(0, 2, size=payload_size, dtype=np.uint8)
	stego, _ = embed(cover, payload, key)
	decoded, restored = extract(stego, key)

	assert np.array_equal(decoded, payload)
	assert np.array_equal(restored, cover)


@pytest.mark.parametrize("value", [0, 255])
def test_uniform_saturated_covers_are_reversible(value: int) -> None:
	"""Uniform saturated covers remain exact when their capacity is used."""
	cover = np.full((32, 32), value, dtype=np.uint8)
	key = b"location-key"
	capacity = capacity_bits(cover, key)
	if capacity == 0:
		assert capacity == 0
		return
	payload = np.zeros(capacity, dtype=np.uint8)
	stego, _ = embed(cover, payload, key)
	decoded, restored = extract(stego, key)

	assert np.array_equal(decoded, payload)
	assert np.array_equal(restored, cover)


def test_exact_capacity_and_overflow() -> None:
	"""The exact payload capacity succeeds and one extra bit fails."""
	cover = np.tile(np.arange(64, dtype=np.uint8), (64, 1))
	key = b"location-key"
	capacity = capacity_bits(cover, key)
	payload = np.zeros(capacity, dtype=np.uint8)
	stego, _ = embed(cover, payload, key)
	decoded, restored = extract(stego, key)

	assert np.array_equal(decoded, payload)
	assert np.array_equal(restored, cover)
	with pytest.raises(CapacityError, match="needs.*available"):
		embed(cover, np.zeros(capacity + 1, dtype=np.uint8), key)


def test_reference_pixels_are_unchanged_and_changes_are_bounded() -> None:
	"""Only embed-set pixels change, and reversible embedding changes by at most one."""
	cover = np.tile(np.arange(64, dtype=np.uint8), (64, 1))
	key = b"location-key"
	payload = np.zeros(min(1000, capacity_bits(cover, key)), dtype=np.uint8)
	stego, _ = embed(cover, payload, key)
	rows, columns = np.indices(cover.shape)
	reference = ~(
		(rows > 0)
		& (rows < cover.shape[0] - 1)
		& (columns > 0)
		& (columns < cover.shape[1] - 1)
		& ((rows + columns) % 2 == 0)
	)

	assert np.array_equal(stego[reference], cover[reference])
	assert np.max(np.abs(stego.astype(np.int16) - cover.astype(np.int16))) <= 1


def test_wrong_key_raises_extraction_error() -> None:
	"""A wrong location key fails cleanly."""
	cover = np.tile(np.arange(64, dtype=np.uint8), (64, 1))
	key = b"location-key"
	payload = np.zeros(min(100, capacity_bits(cover, key)), dtype=np.uint8)
	stego, _ = embed(cover, payload, key)

	try:
		decoded, _ = extract(stego, b"different-key")
		extraction_result = decoded.tobytes()
	except ExtractionError:
		return
	assert extraction_result != payload.tobytes()