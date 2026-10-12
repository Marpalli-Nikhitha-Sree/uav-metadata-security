"""SSA-inspired keyed permutations over payload bits."""

from __future__ import annotations

import hashlib

import numpy as np


def bytes_to_bits(data: bytes) -> np.ndarray:
	"""Convert bytes to a flat uint8 array containing zero and one bits."""
	return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits: np.ndarray) -> bytes:
	"""Pack a zero/one bit array into bytes."""
	values = np.asarray(bits, dtype=np.uint8).reshape(-1)
	if values.size % 8 != 0:
		raise ValueError("Bit array length must be a multiple of 8")
	if np.any(values > 1):
		raise ValueError("Bit array may contain only zero and one")
	return np.packbits(values).tobytes()


def _permutation(length: int, k_shuf: bytes) -> np.ndarray:
	"""Build the deterministic keyed permutation for a bit length."""
	if length < 0:
		raise ValueError("Bit length cannot be negative")
	seed_material = hashlib.sha256(k_shuf + length.to_bytes(8, "big")).digest()
	seed = int.from_bytes(seed_material, "big")
	return np.random.Generator(np.random.PCG64(seed)).permutation(length)


def shuffle(bits: np.ndarray, k_shuf: bytes) -> np.ndarray:
	"""Permute bits deterministically with the shuffle key."""
	values = np.asarray(bits, dtype=np.uint8).reshape(-1)
	return values[_permutation(values.size, k_shuf)]


def unshuffle(bits: np.ndarray, k_shuf: bytes) -> np.ndarray:
	"""Reverse the keyed bit permutation."""
	values = np.asarray(bits, dtype=np.uint8).reshape(-1)
	permutation = _permutation(values.size, k_shuf)
	inverse = np.empty_like(permutation)
	inverse[permutation] = np.arange(values.size)
	return values[inverse]
