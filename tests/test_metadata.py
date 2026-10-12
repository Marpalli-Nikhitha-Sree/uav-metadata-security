"""Tests for EXIF fallback and subtitle telemetry parsing."""

import logging

from PIL import Image

from uavsec.metadata import extract_exif_xmp, parse_srt, telemetry_for_frame


def test_srt_parser_and_frame_lookup(tmp_path) -> None:
	"""DJI-style bracketed fields are parsed and selected by frame time."""
	srt = """1
00:00:00,000 --> 00:00:01,000
[latitude: 12.5] [longitude: -45.25] [altitude: 120.5] [iso: 100] [shutter: 1/1000] [fnum: 2.8] [gb_pitch: -3.0] [gb_yaw: 10.0] [gb_roll: 0.5] [flight_yaw: 90.0] [timestamp: 2026-01-01T00:00:00Z] [mission_id: alpha]
"""
	path = tmp_path / "flight.srt"
	path.write_text(srt, encoding="utf-8")

	entries = parse_srt(path)
	telemetry = telemetry_for_frame(entries, frame_index=15, fps=30)

	assert telemetry["gps_lat"] == 12.5
	assert telemetry["gps_lon"] == -45.25
	assert telemetry["altitude_m"] == 120.5
	assert telemetry["iso"] == 100
	assert telemetry["shutter"] == "1/1000"
	assert telemetry["focal_length"] == 2.8
	assert telemetry["mission_id"] == "alpha"


def test_pillow_fallback_reads_exif_when_exiftool_is_absent(tmp_path, caplog) -> None:
	"""Pillow EXIF metadata remains available without the ExifTool module."""
	image = Image.new("RGB", (2, 2), color="red")
	exif = Image.Exif()
	exif[272] = "Test Camera"
	path = tmp_path / "image.jpg"
	image.save(path, exif=exif)

	with caplog.at_level(logging.WARNING):
		metadata = extract_exif_xmp(path)

	assert metadata["camera_model"] == "Test Camera"
	assert any("falling back to Pillow" in message for message in caplog.messages)