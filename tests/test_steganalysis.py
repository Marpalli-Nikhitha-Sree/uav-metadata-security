"""Tests for optional Aletheia integration."""

from uavsec.steganalysis import run_aletheia


def test_aletheia_not_configured_is_non_fatal(monkeypatch, tmp_path) -> None:
	"""An unset Aletheia path returns an explicit unavailable result."""
	monkeypatch.delenv("ALETHEIA_PATH", raising=False)

	result = run_aletheia(tmp_path / "cover.png")

	assert result["status"] == "not configured"
	assert result["configured"] is False