"""End-to-end UAV metadata protection pipeline."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import numpy as np

from uavsec.capture import extract_keyframe, load_image
from uavsec.cover import cover_hash, load_png, save_stripped_png
from uavsec.crypto import decrypt, encrypt
from uavsec.errors import AuthenticationError, ExtractionError
from uavsec.keys import KeySet
from uavsec.metadata import extract_exif_xmp, parse_srt, telemetry_for_frame
from uavsec.metrics import psnr, ssim
from uavsec.rdh import capacity_bits, embed, extract
from uavsec.serializer import deserialize, filter_metadata, serialize
from uavsec.shuffler import bits_to_bytes, bytes_to_bits, shuffle, unshuffle


@dataclass(frozen=True)
class EncodeResult:
	"""Result returned by a successful encoder run."""

	stego_path: Path
	cover_hash: str
	metadata: dict[str, Any]
	payload_bytes: bytes
	capacity_bits: int
	psnr: float
	ssim: float
	trace: list[dict[str, Any]]


@dataclass(frozen=True)
class DecodeResult:
	"""Result returned by decoder, including failures as verdicts."""

	verdict: str
	metadata: Optional[dict[str, Any]]
	restored_image: Optional[np.ndarray]
	cover_hash_match: Optional[bool]
	trace: list[dict[str, Any]]


def _preview(value: Any) -> Any:
	"""Convert trace data to compact JSON-friendly preview values."""
	if isinstance(value, bytes):
		return value.hex()
	if isinstance(value, np.ndarray):
		return value.reshape(-1).tolist()[:128]
	if isinstance(value, Path):
		return str(value)
	if isinstance(value, dict):
		return {str(key): _preview(item) for key, item in value.items()}
	if isinstance(value, (list, tuple)):
		return [_preview(item) for item in value]
	return value


def _add_trace(
	trace: list[dict[str, Any]], stage: str, summary: str, preview: Any
) -> None:
	"""Append one timed pipeline trace entry."""
	trace.append(
		{
			"stage": stage,
			"summary": summary,
			"duration_ms": 0.0,
			"data_preview": _preview(preview),
		}
	)


def _timed_stage(
	trace: list[dict[str, Any]], stage: str, operation: Any, summary: str
) -> Any:
	"""Run an operation and append its measured trace entry."""
	started = time.perf_counter()
	duration_ms = (time.perf_counter() - started) * 1000
	try:
		result = operation()
	except Exception as error:
		duration_ms = (time.perf_counter() - started) * 1000
		_add_trace(trace, stage, f"{stage.title()} failed", {"error": str(error)})
		trace[-1]["duration_ms"] = duration_ms
		raise
	duration_ms = (time.perf_counter() - started) * 1000
	preview = result if isinstance(result, (dict, bytes, str, int, float)) else result
	_add_trace(trace, stage, summary, preview)
	trace[-1]["duration_ms"] = duration_ms
	return result


def _load_source(source_path: str | Path, frame_index: Optional[int]) -> np.ndarray:
	"""Load a source image or video frame, using PNG fallback when OpenCV is absent."""
	if frame_index is not None:
		return extract_keyframe(source_path, frame_index)
	try:
		return load_image(source_path)
	except ExtractionError as error:
		if "OpenCV is required" not in str(error):
			raise
		return load_png(source_path)


def encode(
	source_path: str | Path,
	keys: KeySet,
	mission_id: str,
	srt_path: str | Path | None = None,
	frame_index: int | None = None,
	out_path: str | Path = "outputs/stego.png",
) -> EncodeResult:
	"""Encode source metadata into a reversible PNG stego image."""
	trace: list[dict[str, Any]] = []
	cover = _timed_stage(trace, "capture", lambda: _load_source(source_path, frame_index), "Source captured")
	cover_hash_hex = _timed_stage(trace, "cover", lambda: cover_hash(cover), "Cover normalized and hashed")
	def collect_metadata() -> dict[str, dict[str, Any]]:
		"""Collect source and optional telemetry metadata."""
		raw_metadata = extract_exif_xmp(source_path)
		entries: list[dict[str, Any]] = []
		if srt_path is not None:
			entries = parse_srt(srt_path)
			if frame_index is not None and entries:
				raw_metadata.update(telemetry_for_frame(entries, frame_index, 1.0))
		raw_metadata["telemetry"] = entries
		raw_metadata["mission_id"] = mission_id
		return {"raw": raw_metadata, "filtered": filter_metadata(raw_metadata)}

	metadata_data = _timed_stage(
		trace, "metadata", collect_metadata, "Metadata extracted and filtered"
	)
	filtered_metadata = metadata_data["filtered"]
	serialized = _timed_stage(
		trace,
		"serialize",
		lambda: serialize(filtered_metadata, cover_hash_hex),
		"Metadata serialized as canonical CBOR",
	)
	ciphertext = _timed_stage(
		trace,
		"encrypt",
		lambda: encrypt(keys.k_enc, serialized, mission_id.encode("utf-8")),
		"Metadata encrypted with AES-GCM",
	)
	cipher_bits = bytes_to_bits(ciphertext)
	shuffled_bits = _timed_stage(
		trace,
		"shuffle",
		lambda: shuffle(cipher_bits, keys.k_shuf),
		"Encrypted bits shuffled",
	)
	trace[-1]["data_preview"] = {
		"before": cipher_bits[:128].tolist(),
		"after": shuffled_bits[:128].tolist(),
	}
	capacity = capacity_bits(cover, keys.k_loc)
	stego, info = _timed_stage(
		trace,
		"embed",
		lambda: embed(cover, shuffled_bits, keys.k_loc),
		"Payload embedded reversibly",
	)
	trace[-1]["data_preview"] = {"capacity": capacity, **info}
	out_file = Path(out_path)
	out_file.parent.mkdir(parents=True, exist_ok=True)
	_timed_stage(trace, "output", lambda: save_stripped_png(stego, out_file), "Metadata-free PNG written")
	return EncodeResult(
		stego_path=out_file,
		cover_hash=cover_hash_hex,
		metadata=filtered_metadata,
		payload_bytes=ciphertext,
		capacity_bits=capacity,
		psnr=psnr(cover, stego),
		ssim=ssim(cover, stego),
		trace=trace,
	)


def decode(stego_path: str | Path, keys: KeySet, mission_id: str) -> DecodeResult:
	"""Decode a stego image without raising for malformed or tampered input."""
	trace: list[dict[str, Any]] = []
	metadata: Optional[dict[str, Any]] = None
	try:
		stego = _timed_stage(trace, "load", lambda: load_png(stego_path), "Stego image loaded")
		shuffled_bits, restored = _timed_stage(
			trace, "extract", lambda: extract(stego, keys.k_loc), "RDH payload extracted"
		)
		cipher_bits = _timed_stage(
			trace, "unshuffle", lambda: unshuffle(shuffled_bits, keys.k_shuf), "Payload bits unshuffled"
		)
		ciphertext = bits_to_bytes(cipher_bits)
		plaintext = _timed_stage(
			trace,
			"decrypt",
			lambda: decrypt(keys.k_enc, ciphertext, mission_id.encode("utf-8")),
			"AES-GCM payload authenticated",
		)
		metadata, expected_hash = deserialize(plaintext)
		actual_hash = cover_hash(restored)
		matches = actual_hash == expected_hash
		_add_trace(trace, "verify", "Restored cover binding verified", {"expected": expected_hash, "actual": actual_hash, "match": matches})
		if not matches:
			return DecodeResult("BINDING_MISMATCH", metadata, restored, False, trace)
		return DecodeResult("AUTHENTIC", metadata, restored, True, trace)
	except (ExtractionError, AuthenticationError) as error:
		stage = "extract" if isinstance(error, ExtractionError) else "decrypt"
		if not trace or trace[-1]["stage"] != stage:
			_add_trace(trace, stage, f"{stage.title()} failed", {"error": str(error)})
		return DecodeResult("TAMPERED_PAYLOAD", metadata, None, None, trace)
	except Exception as error:
		if not trace or trace[-1]["stage"] != "verify":
			_add_trace(trace, "verify", "Decode failed", {"error": str(error)})
		return DecodeResult("TAMPERED_PAYLOAD", metadata, None, None, trace)
