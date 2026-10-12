"""SQLite operation history for the UAV security pipeline."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from uavsec.config import Config


def _database_path(db_path: str | Path | None) -> Path:
	"""Resolve and create the parent directory for a database path."""
	path = Path(db_path) if db_path is not None else Config().sqlite_file
	path.parent.mkdir(parents=True, exist_ok=True)
	return path


def init_db(db_path: str | Path | None = None) -> None:
	"""Create the operations table if it does not already exist."""
	with sqlite3.connect(_database_path(db_path)) as connection:
		_ensure_schema(connection)


def _ensure_schema(connection: sqlite3.Connection) -> None:
	"""Create the operations table on an existing connection."""
	connection.execute(
		"""
		CREATE TABLE IF NOT EXISTS operations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				created_at TEXT NOT NULL,
				kind TEXT NOT NULL CHECK (kind IN ('encode', 'decode')),
				mission_id TEXT NOT NULL,
				filename TEXT NOT NULL,
				cover_hash TEXT,
				payload_bytes INTEGER,
				capacity_bits INTEGER,
				psnr REAL,
				ssim REAL,
				total_ms REAL,
				verdict TEXT,
				trace_json TEXT NOT NULL
			)
		"""
	)


def log_operation(
	kind: str,
	mission_id: str,
	filename: str,
	cover_hash: str | None = None,
	payload_bytes: int | None = None,
	capacity_bits: int | None = None,
	psnr: float | None = None,
	ssim: float | None = None,
	total_ms: float | None = None,
	verdict: str | None = None,
	trace: list[dict[str, Any]] | None = None,
	db_path: str | Path | None = None,
) -> int:
	"""Insert one encode/decode operation and return its database id."""
	if kind not in {"encode", "decode"}:
		raise ValueError("Operation kind must be encode or decode")
	with sqlite3.connect(_database_path(db_path)) as connection:
		_ensure_schema(connection)
		cursor = connection.execute(
			"""
			INSERT INTO operations (
				created_at, kind, mission_id, filename, cover_hash, payload_bytes,
				capacity_bits, psnr, ssim, total_ms, verdict, trace_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				datetime.now(timezone.utc).isoformat(), kind, mission_id, filename,
				cover_hash, payload_bytes, capacity_bits, psnr, ssim, total_ms,
				verdict, json.dumps(trace or []),
			),
		)
		return int(cursor.lastrowid)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
	"""Convert a database row to an API-friendly dictionary."""
	result = dict(row)
	result["trace"] = json.loads(result.pop("trace_json"))
	return result


def list_operations(
	limit: int = 50,
	mission_id: Optional[str] = None,
	db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
	"""List recent operations, optionally restricted to a mission."""
	if limit < 1:
		raise ValueError("limit must be positive")
	with sqlite3.connect(_database_path(db_path)) as connection:
		_ensure_schema(connection)
		connection.row_factory = sqlite3.Row
		if mission_id is None:
			cursor = connection.execute(
				"SELECT * FROM operations ORDER BY id DESC LIMIT ?", (limit,)
			)
		else:
			cursor = connection.execute(
				"SELECT * FROM operations WHERE mission_id = ? ORDER BY id DESC LIMIT ?",
				(mission_id, limit),
			)
		return [_row_to_dict(row) for row in cursor.fetchall()]


def get_operation(
	operation_id: int, db_path: str | Path | None = None
) -> dict[str, Any] | None:
	"""Fetch one operation by id, or return None when it does not exist."""
	with sqlite3.connect(_database_path(db_path)) as connection:
		_ensure_schema(connection)
		connection.row_factory = sqlite3.Row
		cursor = connection.execute("SELECT * FROM operations WHERE id = ?", (operation_id,))
		row = cursor.fetchone()
		return _row_to_dict(row) if row is not None else None
