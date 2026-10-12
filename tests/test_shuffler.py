"""Tests for keyed bit permutation helpers."""

import numpy as np
import pytest

from uavsec.shuffler import bits_to_bytes, bytes_to_bits, shuffle, unshuffle


@pytest.mark.parametrize("length", [1, 8, 1000, 4097])
def test_unshuffle_restores_bits(length: int) -> None:
	"""Unshuffling a shuffle restores every tested bit length."""
	rng = np.random.default_rng(length)
	bits = rng.integers(0, 2, size=length, dtype=np.uint8)

	assert np.array_equal(unshuffle(shuffle(bits, b"key"), b"key"), bits)


def test_wrong_key_does_not_restore() -> None:
	"""A different key does not reverse the original permutation."""
	bits = bytes_to_bits(b"payload")

	assert not np.array_equal(unshuffle(shuffle(bits, b"key-a"), b"key-b"), bits)


def test_shuffle_preserves_one_count_and_byte_helpers_round_trip() -> None:
	"""Permutation preserves Hamming weight and byte conversion is lossless."""
	bits = bytes_to_bits(b"payload")
	shuffled = shuffle(bits, b"key")

	assert np.count_nonzero(shuffled) == np.count_nonzero(bits)
	assert bits_to_bytes(bits) == b"payload"