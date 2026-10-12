"""Canonical CBOR serialization for authenticated UAV metadata."""

from __future__ import annotations

from typing import Any, Mapping

import cbor2

from uavsec.config import Config


def filter_metadata(raw: Mapping[str, Any]) -> dict[str, Any]:
	"""Keep configured metadata fields whose values are not null."""
	whitelist = Config().metadata_whitelist
	return {
		key: raw[key]
		for key in whitelist
		if key in raw and raw[key] is not None
	}


def serialize(filtered: Mapping[str, Any], cover_hash_hex: str) -> bytes:
	"""Encode metadata and a 32-byte cover hash as canonical CBOR."""
	try:
		cover_hash = bytes.fromhex(cover_hash_hex)
	except ValueError as error:
		raise ValueError("cover_hash_hex must contain hexadecimal bytes") from error
	if len(cover_hash) != 32:
		raise ValueError("cover_hash_hex must represent exactly 32 bytes")
	payload = {"metadata": dict(filtered), "cover_hash": cover_hash}
	return cbor2.dumps(payload, canonical=True)


def deserialize(data: bytes) -> tuple[dict[str, Any], str]:
	"""Decode canonical metadata and return its cover hash as lowercase hex."""
	payload = cbor2.loads(data)
	if not isinstance(payload, dict):
		raise ValueError("Serialized metadata must contain a CBOR map")
	metadata = payload.get("metadata")
	cover_hash = payload.get("cover_hash")
	if not isinstance(metadata, dict) or not isinstance(cover_hash, bytes):
		raise ValueError("Serialized metadata has an invalid structure")
	if len(cover_hash) != 32:
		raise ValueError("Serialized cover hash must be exactly 32 bytes")
	return metadata, cover_hash.hex()
