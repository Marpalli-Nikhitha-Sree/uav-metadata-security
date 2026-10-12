"""End-to-end pipeline tests."""

import numpy as np
from PIL import Image

from uavsec.keys import derive_keys
from uavsec.pipeline import decode, encode


def test_encode_decode_round_trip_and_trace(tmp_path) -> None:
	"""Encoding and decoding preserve metadata, pixels, and ordered traces."""
	cover = np.tile(np.arange(128, dtype=np.uint8), (128, 1))
	source = tmp_path / "source.png"
	out_path = tmp_path / "stego.png"
	Image.fromarray(cover).save(source)
	keys = derive_keys(bytes(range(32)), "mission-7")

	encoded = encode(source, keys, "mission-7", out_path=out_path)
	decoded = decode(out_path, keys, "mission-7")

	assert decoded.verdict == "AUTHENTIC"
	assert decoded.metadata == encoded.metadata
	assert np.array_equal(decoded.restored_image, cover)
	assert decoded.cover_hash_match is True
	assert [entry["stage"] for entry in encoded.trace] == [
		"capture", "cover", "metadata", "serialize", "encrypt", "shuffle", "embed", "output"
	]
	assert [entry["stage"] for entry in decoded.trace] == [
		"load", "extract", "unshuffle", "decrypt", "verify"
	]
	with Image.open(out_path) as image:
		assert image.info == {}


def test_tampered_inputs_return_verdicts_without_raising(tmp_path) -> None:
	"""Pixel tampering, JPEG conversion, and wrong keys are non-authentic."""
	cover = np.tile(np.arange(128, dtype=np.uint8), (128, 1))
	source = tmp_path / "source.png"
	out_path = tmp_path / "stego.png"
	Image.fromarray(cover).save(source)
	keys = derive_keys(bytes(range(32)), "mission-7")
	encode(source, keys, "mission-7", out_path=out_path)

	with Image.open(out_path) as image:
		pixels = np.array(image)
	pixels[64, 64] ^= 1
	Image.fromarray(pixels).save(out_path)
	assert decode(out_path, keys, "mission-7").verdict != "AUTHENTIC"

	jpeg_path = tmp_path / "stego.jpg"
	Image.fromarray(pixels).save(jpeg_path, quality=50)
	assert decode(jpeg_path, keys, "mission-7").verdict != "AUTHENTIC"

	wrong_keys = derive_keys(bytes(reversed(range(32))), "mission-7")
	assert decode(out_path, wrong_keys, "mission-7").verdict != "AUTHENTIC"