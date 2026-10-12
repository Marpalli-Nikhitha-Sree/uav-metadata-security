"""Tests for SQLite operation logging."""

from uavsec.db import get_operation, init_db, list_operations, log_operation


def test_operation_crud(tmp_path) -> None:
	"""Operations are inserted and queried with structured traces."""
	database = tmp_path / "operations.sqlite3"
	init_db(database)
	operation_id = log_operation(
		"encode",
		"mission-7",
		"cover.png",
		cover_hash="ab",
		trace=[{"stage": "cover"}],
		db_path=database,
	)

	operation = get_operation(operation_id, database)
	operations = list_operations(10, "mission-7", database)

	assert operation["trace"] == [{"stage": "cover"}]
	assert operations[0]["id"] == operation_id