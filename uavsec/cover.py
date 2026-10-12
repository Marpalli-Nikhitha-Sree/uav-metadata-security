"""Cover-image normalization, hashing, and metadata-free PNG I/O."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import numpy as np
from PIL import Image

from uavsec.errors import ExtractionError


def _uint8_array(array: np.ndarray) -> np.ndarray:
	"""Convert numeric pixel data to a clipped uint8 array."""
	values = np.asarray(array)
	if not np.issubdtype(values.dtype, np.number):
		raise ValueError("Pixel array must contain numeric values")
	return np.clip(values, 0, 255).astype(np.uint8, copy=False)


def preprocess(array: np.ndarray) -> np.ndarray:
	"""Return an 8-bit grayscale or RGB cover with alpha removed."""
	values = _uint8_array(array)
	if values.ndim == 2:
		return np.ascontiguousarray(values)
	if values.ndim != 3:
		raise ValueError("Pixel array must be HxW grayscale or HxWxC color data")
	if values.shape[2] == 1:
		return np.ascontiguousarray(values[:, :, 0])
	if values.shape[2] >= 3:
		return np.ascontiguousarray(values[:, :, :3])
	raise ValueError("Pixel array must have one, three, or four channels")


def cover_hash(array: np.ndarray) -> str:
	"""Hash the normalized cover shape and raw pixel bytes with SHA-256."""
	cover = preprocess(array)
	hasher = hashlib.sha256()
	hasher.update(struct.pack(">I", cover.ndim))
	for dimension in cover.shape:
		hasher.update(struct.pack(">Q", dimension))
	hasher.update(cover.tobytes(order="C"))
	return hasher.hexdigest()


def save_stripped_png(array: np.ndarray, path: str | Path) -> None:
	"""Save a normalized cover as a PNG without application metadata."""
	cover = preprocess(array)
	image = Image.fromarray(cover, mode="L" if cover.ndim == 2 else "RGB")
	image.save(path, format="PNG", exif=b"", pnginfo=None)


def load_png(path: str | Path) -> np.ndarray:
	"""Load a PNG as a normalized uint8 grayscale or RGB array."""
	try:
		with Image.open(path) as image:
			return preprocess(np.array(image.convert("L" if image.mode == "L" else "RGB")))
	except (OSError, ValueError) as error:
		raise ExtractionError(f"Unable to read PNG file: {path}") from error
