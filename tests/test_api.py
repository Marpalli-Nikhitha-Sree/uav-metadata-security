"""FastAPI integration tests."""

import io

import numpy as np
from fastapi.testclient import TestClient
from PIL import Image

from api.main import app


def _image_upload() -> io.BytesIO:
	"""Build a smooth PNG with enough RDH capacity for integration tests."""
	image = np.tile(np.arange(128, dtype=np.uint8), (128, 1))
	buffer = io.BytesIO()
	Image.fromarray(image).save(buffer, format="PNG")
	buffer.seek(0)
	return buffer


def test_api_round_trip_attacks_and_health(tmp_path, monkeypatch) -> None:
	"""The API encodes, decodes, attacks, and logs operations."""
	monkeypatch.setenv("UAVSEC_MASTER_KEY", bytes(range(32)).hex())
	with TestClient(app) as client:
		assert client.get("/health").json()["status"] == "ok"
		response = client.post(
			"/encode",
			files={"file": ("cover.png", _image_upload(), "image/png")},
			data={"mission_id": "mission-7"},
		)
		assert response.status_code == 200
		encoded = response.json()
		stego_response = client.get(f"/files/{encoded['download_id']}")
		decoded = client.post(
			"/decode",
			files={"file": ("stego.png", stego_response.content, "image/png")},
			data={"mission_id": "mission-7"},
		).json()
		assert decoded["verdict"] == "AUTHENTIC"
		assert decoded["restored_image_id"]
		for attack_type in ("pixel_flip", "jpeg", "crop_pad", "noise"):
			attacked = client.post(
				"/attack",
				files={"file": ("stego.png", stego_response.content, "image/png")},
				data={"attack_type": attack_type},
			).json()
			attacked_file = client.get(f"/files/{attacked['download_id']}")
			attack_decode = client.post(
				"/decode",
				files={"file": ("attacked.png", attacked_file.content, "image/png")},
				data={"mission_id": "mission-7"},
			).json()
			assert attack_decode["verdict"] != "AUTHENTIC"
		assert client.get("/operations").json()


def test_api_rejects_invalid_file(monkeypatch) -> None:
	"""Unsupported uploads receive a client error."""
	monkeypatch.setenv("UAVSEC_MASTER_KEY", bytes(range(32)).hex())
	with TestClient(app) as client:
		response = client.post(
			"/decode",
			files={"file": ("payload.txt", b"not an image", "text/plain")},
			data={"mission_id": "mission-7"},
		)
	assert response.status_code in {400, 415}