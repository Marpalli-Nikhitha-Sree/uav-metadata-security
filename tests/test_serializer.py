"""Tests for metadata filtering and canonical CBOR."""

from uavsec.serializer import deserialize, filter_metadata, serialize


def test_cbor_round_trip_and_filtering() -> None:
	"""Whitelisted values and the raw cover hash survive serialization."""
	raw = {
		"Make": "UAVCo",
		"Model": None,
		"GPSLatitude": 12.5,
		"not_allowed": "drop me",
	}
	filtered = filter_metadata(raw)
	cover_hash = "ab" * 32

	metadata, decoded_hash = deserialize(serialize(filtered, cover_hash))

	assert filtered == {"Make": "UAVCo", "GPSLatitude": 12.5}
	assert metadata == filtered
	assert decoded_hash == cover_hash


def test_canonical_serialization_is_stable() -> None:
	"""Equivalent mappings serialize to identical canonical CBOR."""
	cover_hash = "01" * 32

	assert serialize({"Model": "X", "Make": "Y"}, cover_hash) == serialize(
		{"Make": "Y", "Model": "X"}, cover_hash
	)