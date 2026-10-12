"""Master-key loading and mission-scoped key derivation."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from uavsec.config import Config


KEY_LENGTH = 32


@dataclass(frozen=True)
class KeySet:
	"""Hold the three 256-bit keys used by the pipeline."""

	k_enc: bytes
	k_shuf: bytes
	k_loc: bytes


def generate_master_key() -> bytes:
	"""Generate a cryptographically secure 256-bit master key."""
	return os.urandom(KEY_LENGTH)


def _decode_key(raw_key: str, source: str) -> bytes:
	"""Decode and validate a hexadecimal master key."""
	try:
		key = bytes.fromhex(raw_key.strip())
	except ValueError as error:
		raise ValueError(f"Master key from {source} must be hexadecimal") from error
	if len(key) != KEY_LENGTH:
		raise ValueError(f"Master key from {source} must decode to exactly 32 bytes")
	return key


def load_master_key(key_path: Optional[Path] = None) -> bytes:
	"""Load a 32-byte master key from the environment or a hex file."""
	environment_key = os.environ.get("UAVSEC_MASTER_KEY")
	if environment_key is not None:
		return _decode_key(environment_key, "UAVSEC_MASTER_KEY")

	configured_path = key_path or Config().master_key_file
	try:
		key_text = configured_path.read_text(encoding="ascii")
	except FileNotFoundError as error:
		raise ValueError(
			"Master key is missing: set UAVSEC_MASTER_KEY or create "
			f"{configured_path}"
		) from error
	except OSError as error:
		raise ValueError(f"Unable to read master key file {configured_path}") from error
	return _decode_key(key_text, str(configured_path))


def _derive_key(master_key: bytes, mission_id: str, info: bytes) -> bytes:
	"""Derive one 256-bit mission key with HKDF-SHA256."""
	return HKDF(
		algorithm=hashes.SHA256(),
		length=KEY_LENGTH,
		salt=mission_id.encode("utf-8"),
		info=info,
	).derive(master_key)


def derive_keys(master: bytes, mission_id: str) -> KeySet:
	"""Derive encryption, shuffle, and location keys for a mission."""
	if len(master) != KEY_LENGTH:
		raise ValueError("Master key must be exactly 32 bytes")
	config = Config()
	return KeySet(
		k_enc=_derive_key(master, mission_id, config.hkdf_info_enc),
		k_shuf=_derive_key(master, mission_id, config.hkdf_info_shuf),
		k_loc=_derive_key(master, mission_id, config.hkdf_info_loc),
	)
