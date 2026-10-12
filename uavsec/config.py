"""Immutable project configuration for UAV metadata security."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
	"""Store all paths and fixed metadata/key-derivation settings."""

	data_dir: Path = Path("data")
	outputs_dir: Path = Path("outputs")
	sqlite_file: Path = Path("data/uavsec.sqlite3")
	master_key_file: Path = Path("data/master.key")
	metadata_whitelist: tuple[str, ...] = field(
		default=(
			"Make",
			"Model",
			"DateTimeOriginal",
			"GPSLatitude",
			"GPSLongitude",
			"GPSAltitude",
			"XMP:DroneModel",
			"XMP:MissionId",
			"telemetry",
		)
	)
	hkdf_info_enc: bytes = b"uav-rdh/enc"
	hkdf_info_shuf: bytes = b"uav-rdh/shuf"
	hkdf_info_loc: bytes = b"uav-rdh/loc"
