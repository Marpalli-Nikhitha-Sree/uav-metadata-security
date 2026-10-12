"""Tests for cover normalization and metadata-free PNG output."""

import numpy as np
from PIL import Image

from uavsec.cover import cover_hash, load_png, save_stripped_png


def test_cover_hash_is_stable_and_pixel_sensitive() -> None:
	"""The same pixels hash identically and one changed pixel does not."""
	cover = np.zeros((4, 5, 3), dtype=np.uint8)
	changed = cover.copy()
	changed[1, 2, 0] = 1

	assert cover_hash(cover) == cover_hash(cover.copy())
	assert cover_hash(cover) != cover_hash(changed)


def test_saved_png_reloads_bit_exact_without_metadata(tmp_path) -> None:
	"""PNG round trips preserve pixels and contain no ancillary metadata."""
	cover = np.arange(60, dtype=np.uint8).reshape(4, 5, 3)
	path = tmp_path / "cover.png"

	save_stripped_png(cover, path)

	assert np.array_equal(load_png(path), cover)
	with Image.open(path) as image:
		assert image.info == {}