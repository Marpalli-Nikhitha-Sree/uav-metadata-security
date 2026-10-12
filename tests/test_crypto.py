"""Tests for AES-GCM encryption and authentication failures."""

import pytest

from uavsec.crypto import decrypt, encrypt
from uavsec.errors import AuthenticationError


def test_encrypt_decrypt_round_trip() -> None:
	"""Authenticated plaintext decrypts with the matching key and AAD."""
	key = bytes(range(32))
	aad = b"mission-7"
	plaintext = b"canonical metadata"

	assert decrypt(key, encrypt(key, plaintext, aad), aad) == plaintext


def test_encryptions_use_fresh_nonces() -> None:
	"""Encrypting equal inputs twice produces different blobs."""
	key = bytes(range(32))

	assert encrypt(key, b"same", b"mission-7") != encrypt(key, b"same", b"mission-7")


def test_flipped_ciphertext_bit_raises() -> None:
	"""A flipped ciphertext bit, wrong key, and wrong AAD are rejected."""
	key = bytes(range(32))
	blob = encrypt(key, b"payload", b"mission-7")
	bad_blob = blob[:20] + bytes([blob[20] ^ 1]) + blob[21:]

	with pytest.raises(AuthenticationError):
		decrypt(key, bad_blob, b"mission-7")


def test_wrong_key_and_aad_raise() -> None:
	"""A wrong key or AAD is rejected by AES-GCM authentication."""
	key = bytes(range(32))
	blob = encrypt(key, b"payload", b"mission-7")

	with pytest.raises(AuthenticationError):
		decrypt(bytes(reversed(range(32))), blob, b"mission-7")
	with pytest.raises(AuthenticationError):
		decrypt(key, blob, b"mission-8")