"""Prediction-error expansion and reversible data hiding."""

from __future__ import annotations

import hashlib
import zlib
from typing import Any

import numpy as np

from uavsec.cover import preprocess
from uavsec.errors import CapacityError, ExtractionError


_HEADER_BITS = 64


def _shape_bytes(shape: tuple[int, ...]) -> bytes:
	"""Encode an array shape for keyed-order derivation."""
	return np.asarray(shape, dtype=np.int64).tobytes()


def _embed_mask(shape: tuple[int, ...]) -> np.ndarray:
	"""Return the spatial interior checkerboard mask, broadcast by channel."""
	if len(shape) not in (2, 3) or shape[0] < 3 or shape[1] < 3:
		return np.zeros(shape, dtype=bool)
	rows, columns = np.indices(shape[:2])
	spatial = (
		(rows > 0)
		& (rows < shape[0] - 1)
		& (columns > 0)
		& (columns < shape[1] - 1)
		& ((rows + columns) % 2 == 0)
	)
	return spatial if len(shape) == 2 else np.broadcast_to(spatial[..., None], shape)


def _keyed_order(cover: np.ndarray, k_loc: bytes) -> np.ndarray:
	"""Return a keyed permutation of flattened embed-set indices."""
	mask = _embed_mask(cover.shape)
	indices = np.flatnonzero(mask.reshape(-1))
	seed_material = hashlib.sha256(k_loc + _shape_bytes(cover.shape)).digest()
	seed = int.from_bytes(seed_material, "big")
	return indices[np.random.Generator(np.random.PCG64(seed)).permutation(indices.size)]


def _prediction(cover: np.ndarray) -> np.ndarray:
	"""Compute four-neighbor predictions in int32 for every pixel."""
	values = cover.astype(np.int32, copy=False)
	prediction = values.copy()
	prediction[1:-1, 1:-1, ...] = (
		values[:-2, 1:-1, ...]
		+ values[2:, 1:-1, ...]
		+ values[1:-1, :-2, ...]
		+ values[1:-1, 2:, ...]
	) // 4
	return prediction


def _state(cover: np.ndarray, k_loc: bytes) -> dict[str, Any]:
	"""Prepare clipped pixels, predictions, order, map, and usable bins."""
	values = preprocess(cover)
	work = values.astype(np.int32, copy=True)
	mask = _embed_mask(values.shape)
	flat_work = work.reshape(-1)
	flat_mask = mask.reshape(-1)
	embed_indices = np.flatnonzero(flat_mask)
	clipping_bits = np.isin(flat_work[embed_indices], (0, 255))
	flat_work[embed_indices] = np.clip(flat_work[embed_indices], 1, 254)
	order = _keyed_order(values, k_loc)
	prediction = _prediction(work)
	error = work - prediction
	ordered_error = error.reshape(-1)[order]
	usable = (ordered_error == 0) | (ordered_error == -1)
	ordered_embed_positions = np.searchsorted(embed_indices, order)
	ordered_clipping_bits = clipping_bits[ordered_embed_positions]
	map_bytes = zlib.compress(np.packbits(ordered_clipping_bits).tobytes())
	return {
		"cover": values,
		"work": work,
		"prediction": prediction,
		"order": order,
		"usable": usable,
		"map_bytes": map_bytes,
		"clipping_bits": ordered_clipping_bits,
	}


def _validate_bits(bits: np.ndarray) -> np.ndarray:
	"""Return a flat binary uint8 array."""
	values = np.asarray(bits, dtype=np.uint8).reshape(-1)
	if np.any(values > 1):
		raise ValueError("Payload bits must contain only zero and one")
	return values


def capacity_bits(cover: np.ndarray, k_loc: bytes) -> int:
	"""Return payload capacity after stream header and clipping-map overhead."""
	state = _state(cover, k_loc)
	available = int(np.count_nonzero(state["usable"]))
	overhead = _HEADER_BITS + len(state["map_bytes"]) * 8
	return max(0, available - overhead)


def embed(
	cover: np.ndarray, payload_bits: np.ndarray, k_loc: bytes
) -> tuple[np.ndarray, dict[str, int]]:
	"""Embed payload bits reversibly and return stego pixels plus statistics."""
	state = _state(cover, k_loc)
	payload = _validate_bits(payload_bits)
	map_bits = np.unpackbits(np.frombuffer(state["map_bytes"], dtype=np.uint8))
	stream = np.concatenate(
		[
			np.unpackbits(np.asarray([len(state["map_bytes"])], dtype=">u4").view(np.uint8)),
			np.unpackbits(np.asarray([payload.size], dtype=">u4").view(np.uint8)),
			map_bits,
			payload,
		]
	)
	usable_count = int(np.count_nonzero(state["usable"]))
	available = max(0, usable_count - _HEADER_BITS - map_bits.size)
	if payload.size > available:
		raise CapacityError(
			f"Payload needs {payload.size} bits; available capacity is {available} bits"
		)
	stream_length = stream.size
	if stream_length == 0:
		return state["work"].astype(np.uint8), {
			"capacity": available,
			"used_pixels": 0,
			"map_size": len(state["map_bytes"]),
		}
	usable_positions = np.flatnonzero(state["usable"])
	cutoff = int(usable_positions[stream_length - 1])
	visited = state["order"][: cutoff + 1]
	visited_error = state["work"].reshape(-1)[visited] - state["prediction"].reshape(-1)[visited]
	visited_usable = (visited_error == 0) | (visited_error == -1)
	stream_values = stream[np.cumsum(visited_usable) - 1].astype(np.int32)
	new_error = visited_error.copy()
	zero_error = visited_error == 0
	minus_one_error = visited_error == -1
	new_error[zero_error] = stream_values[zero_error]
	new_error[minus_one_error] = -1 - stream_values[minus_one_error]
	positive_error = visited_error > 0
	negative_error = visited_error < -1
	new_error[positive_error] = visited_error[positive_error] + 1
	new_error[negative_error] = visited_error[negative_error] - 1
	flat_stego = state["work"].reshape(-1).copy()
	flat_stego[visited] = state["prediction"].reshape(-1)[visited] + new_error
	return flat_stego.reshape(state["cover"].shape).astype(np.uint8), {
		"capacity": available,
		"used_pixels": cutoff + 1,
		"map_size": len(state["map_bytes"]),
	}


def _bits_to_uint32(bits: np.ndarray) -> int:
	"""Decode exactly 32 big-endian bits."""
	return int.from_bytes(np.packbits(bits).tobytes(), "big")


def extract(stego: np.ndarray, k_loc: bytes) -> tuple[np.ndarray, np.ndarray]:
	"""Extract a payload and restore the original cover bit-for-bit."""
	try:
		values = preprocess(stego)
		state = _state(values, k_loc)
		prediction = _prediction(values)
		error = values.astype(np.int32).reshape(-1) - prediction.reshape(-1)
		ordered_error = error[state["order"]]
		candidate = (ordered_error >= -2) & (ordered_error <= 1)
		candidate_positions = np.flatnonzero(candidate)
		if candidate_positions.size < _HEADER_BITS:
			raise ExtractionError("RDH stream does not contain a complete header")
		candidate_bits = np.where(
			(ordered_error[candidate_positions] == 0)
			| (ordered_error[candidate_positions] == 1),
			ordered_error[candidate_positions],
			-1 - ordered_error[candidate_positions],
		).astype(np.uint8)
		map_length = _bits_to_uint32(candidate_bits[:32])
		payload_length = _bits_to_uint32(candidate_bits[32:64])
		map_bit_length = map_length * 8
		total_length = _HEADER_BITS + map_bit_length + payload_length
		if map_length == 0 or total_length > candidate_bits.size:
			raise ExtractionError("RDH stream lengths are implausible or incomplete")
		if total_length > int(np.count_nonzero(state["usable"])) + _HEADER_BITS + map_bit_length:
			raise ExtractionError("RDH stream length exceeds image capacity")
		stream_bits = candidate_bits[:total_length]
		try:
			map_data = np.packbits(stream_bits[_HEADER_BITS : _HEADER_BITS + map_bit_length]).tobytes()
			clipping_bits = np.unpackbits(np.frombuffer(zlib.decompress(map_data), dtype=np.uint8))
		except (zlib.error, ValueError) as error:
			raise ExtractionError("RDH clipping map is invalid") from error
		embed_count = state["order"].size
		if clipping_bits.size < embed_count:
			raise ExtractionError("RDH clipping map is shorter than the embed set")
		clipping_bits = clipping_bits[:embed_count]
		selected_positions = candidate_positions[:total_length]
		cutoff = int(selected_positions[-1])
		selected_error = ordered_error[selected_positions]
		restored_error = error.copy()
		ordered_restored = restored_error[state["order"]]
		before_cutoff = np.arange(state["order"].size) <= cutoff
		reverse_positive = before_cutoff & (ordered_restored > 1)
		reverse_negative = before_cutoff & (ordered_restored < -2)
		ordered_restored[reverse_positive] -= 1
		ordered_restored[reverse_negative] += 1
		selected_zero = (selected_error == 0) | (selected_error == 1)
		selected_restored = np.where(selected_zero, 0, -1)
		ordered_restored[selected_positions] = selected_restored
		restored_error[state["order"]] = ordered_restored
		flat_restored = (
			prediction.reshape(-1) + restored_error
		).astype(np.int32)
		ordered_values = flat_restored[state["order"]]
		undo_zero = (clipping_bits == 1) & (ordered_values == 1)
		undo_max = (clipping_bits == 1) & (ordered_values == 254)
		if np.any((clipping_bits == 1) & ~((ordered_values == 1) | (ordered_values == 254))):
			raise ExtractionError("RDH clipping map does not match restored pixels")
		ordered_values[undo_zero] = 0
		ordered_values[undo_max] = 255
		flat_restored[state["order"]] = ordered_values
		if np.any((flat_restored < 0) | (flat_restored > 255)):
			raise ExtractionError("RDH restoration produced an invalid pixel value")
		payload_start = _HEADER_BITS + map_bit_length
		return (
			stream_bits[payload_start : payload_start + payload_length],
			flat_restored.reshape(values.shape).astype(np.uint8),
		)
	except ExtractionError:
		raise
	except Exception as error:
		raise ExtractionError("Unable to extract RDH payload") from error
