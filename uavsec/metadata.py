"""EXIF, XMP, and subtitle telemetry normalization."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from PIL import ExifTags, Image

LOGGER = logging.getLogger(__name__)

METADATA_KEYS = (
	"gps_lat",
	"gps_lon",
	"altitude_m",
	"timestamp_utc",
	"camera_model",
	"gimbal_pitch",
	"gimbal_yaw",
	"gimbal_roll",
	"flight_yaw",
	"iso",
	"shutter",
	"focal_length",
	"mission_id",
)

_ALIASES = {
	"latitude": "gps_lat",
	"lat": "gps_lat",
	"gpslatitude": "gps_lat",
	"longitude": "gps_lon",
	"lon": "gps_lon",
	"lng": "gps_lon",
	"gpslongitude": "gps_lon",
	"altitude": "altitude_m",
	"alt": "altitude_m",
	"rel_alt": "altitude_m",
	"abs_alt": "altitude_m",
	"gpsaltitude": "altitude_m",
	"timestamp": "timestamp_utc",
	"datetimeoriginal": "timestamp_utc",
	"model": "camera_model",
	"cameramodel": "camera_model",
	"gimbal_pitch": "gimbal_pitch",
	"gb_pitch": "gimbal_pitch",
	"gimbalpitchdegree": "gimbal_pitch",
	"gimbal_yaw": "gimbal_yaw",
	"gb_yaw": "gimbal_yaw",
	"gimbalyawdegree": "gimbal_yaw",
	"gimbal_roll": "gimbal_roll",
	"gb_roll": "gimbal_roll",
	"gimbalrolldegree": "gimbal_roll",
	"flight_yaw": "flight_yaw",
	"flightyawdegree": "flight_yaw",
	"yaw": "flight_yaw",
	"iso": "iso",
	"isospeedratings": "iso",
	"shutter": "shutter",
	"exposuretime": "shutter",
	"fnum": "focal_length",
	"focal_length": "focal_length",
	"focallength": "focal_length",
	"mission_id": "mission_id",
	"missionid": "mission_id",
}


def _empty_metadata() -> dict[str, Any]:
	"""Create a metadata dictionary with the normalized public keys."""
	return {key: None for key in METADATA_KEYS}


def _number(value: Any) -> Any:
	"""Convert numeric strings to integers or floats while preserving other values."""
	if isinstance(value, (int, float)):
		return value
	text = str(value).strip()
	try:
		parsed = float(text)
		return int(parsed) if parsed.is_integer() else parsed
	except ValueError:
		return value


def _dms_to_decimal(value: Any) -> Optional[float]:
	"""Convert an EXIF GPS coordinate to decimal degrees."""
	if isinstance(value, (int, float)):
		return float(value)
	try:
		parts = list(value)
		return float(parts[0]) + float(parts[1]) / 60 + float(parts[2]) / 3600
	except (TypeError, ValueError, IndexError):
		return _number(value)


def _normalise_values(values: dict[str, Any]) -> dict[str, Any]:
	"""Map EXIF, XMP, or SRT names to the flat metadata contract."""
	metadata = _empty_metadata()
	for raw_key, value in values.items():
		key = str(raw_key).split(":")[-1].replace(" ", "").lower()
		canonical = _ALIASES.get(key)
		if canonical is None:
			continue
		if canonical in ("gps_lat", "gps_lon"):
			value = _dms_to_decimal(value)
		elif canonical not in ("camera_model", "timestamp_utc", "shutter", "mission_id"):
			value = _number(value)
		metadata[canonical] = value
	return metadata


def _extract_with_exiftool(path: Path) -> dict[str, Any]:
	"""Extract raw metadata through PyExifTool."""
	import exiftool

	with exiftool.ExifToolHelper() as helper:
		result = helper.get_metadata(str(path))
	return result[0] if result else {}


def _extract_with_pillow(path: Path) -> dict[str, Any]:
	"""Extract the available EXIF fields through Pillow."""
	with Image.open(path) as image:
		exif = image.getexif()
		values: dict[str, Any] = {}
		for tag_id, value in exif.items():
			name = ExifTags.TAGS.get(tag_id, str(tag_id))
			values[name] = value
		gps = exif.get(ExifTags.Base.GPSInfo)
		if gps:
			gps_values = {
				ExifTags.GPSTAGS.get(tag_id, str(tag_id)): value
				for tag_id, value in gps.items()
			}
			values.update(gps_values)
		return values


def extract_exif_xmp(path: str | Path) -> dict[str, Any]:
	"""Extract and normalize EXIF/XMP metadata, with a Pillow fallback."""
	metadata_path = Path(path)
	try:
		raw_values = _extract_with_exiftool(metadata_path)
	except (ImportError, OSError, FileNotFoundError) as error:
		LOGGER.warning("PyExifTool unavailable; falling back to Pillow: %s", error)
		raw_values = _extract_with_pillow(metadata_path)
	return _normalise_values(raw_values)


def _srt_seconds(timestamp: str) -> float:
	"""Convert an SRT timestamp to seconds."""
	match = re.fullmatch(r"(\d+):(\d{2}):(\d{2}),(\d{3})", timestamp.strip())
	if match is None:
		raise ValueError(f"Invalid SRT timestamp: {timestamp}")
	hours, minutes, seconds, milliseconds = (int(part) for part in match.groups())
	return hours * 3600 + minutes * 60 + seconds + milliseconds / 1000


def _parse_srt_block(block: str, block_index: int) -> dict[str, Any]:
	"""Parse one subtitle block into timing and normalized telemetry."""
	lines = [line.strip() for line in block.splitlines() if line.strip()]
	if len(lines) < 2:
		raise ValueError("SRT block must contain an index and timing line")
	timing = re.match(r"([^ ]+)\s+-->\s+([^ ]+)", lines[1])
	if timing is None:
		raise ValueError(f"Invalid SRT timing in block {block_index}")
	values: dict[str, Any] = {}
	for key, value in re.findall(r"(?:\[|\b)([A-Za-z][A-Za-z0-9_ ]*)\s*[:=]\s*([^\]\n]+)", " ".join(lines[2:])):
		values[key.strip().replace(" ", "_")] = value.strip()
	entry = _normalise_values(values)
	entry["start_seconds"] = _srt_seconds(timing.group(1))
	entry["end_seconds"] = _srt_seconds(timing.group(2))
	entry["subtitle_index"] = block_index
	return entry


def parse_srt(srt_path: str | Path) -> list[dict[str, Any]]:
	"""Parse DJI-style SRT subtitle blocks into normalized telemetry entries."""
	text = Path(srt_path).read_text(encoding="utf-8-sig")
	entries: list[dict[str, Any]] = []
	for block_index, block in enumerate(re.split(r"\n\s*\n", text.strip()), start=1):
		if block.strip():
			entries.append(_parse_srt_block(block, block_index))
	return entries


def telemetry_for_frame(
	srt_entries: Iterable[dict[str, Any]], frame_index: int, fps: float
) -> dict[str, Any]:
	"""Return the subtitle telemetry covering a frame timestamp."""
	if frame_index < 0 or fps <= 0:
		raise ValueError("frame_index must be non-negative and fps must be positive")
	target_seconds = frame_index / fps
	entries = list(srt_entries)
	for entry in entries:
		if entry["start_seconds"] <= target_seconds <= entry["end_seconds"]:
			return {key: entry.get(key) for key in METADATA_KEYS}
	if not entries:
		return _empty_metadata()
	nearest = min(entries, key=lambda entry: abs(entry["start_seconds"] - target_seconds))
	return {key: nearest.get(key) for key in METADATA_KEYS}
