"""AES-256-GCM encryption for serialized mission metadata."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from uavsec.errors import AuthenticationError


NONCE_LENGTH = 12


def encrypt(k_enc: bytes, plaintext: bytes, aad: bytes) -> bytes:
	"""Encrypt plaintext and return nonce, ciphertext, and tag concatenated."""
	nonce = os.urandom(NONCE_LENGTH)
	return nonce + AESGCM(k_enc).encrypt(nonce, plaintext, aad)


def decrypt(k_enc: bytes, blob: bytes, aad: bytes) -> bytes:
	"""Decrypt an authenticated blob or raise AuthenticationError."""
	try:
		if len(blob) < NONCE_LENGTH + 16:
			raise ValueError("Encrypted blob is shorter than nonce and authentication tag")
		nonce = blob[:NONCE_LENGTH]
		return AESGCM(k_enc).decrypt(nonce, blob[NONCE_LENGTH:], aad)
	except Exception as error:
		raise AuthenticationError("Encrypted payload authentication failed") from error
