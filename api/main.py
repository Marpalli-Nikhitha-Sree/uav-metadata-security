"""FastAPI service for UAV metadata protection and verification."""

from __future__ import annotations
import io
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
import numpy as np
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from PIL import Image

from uavsec.cover import save_stripped_png
from uavsec.db import get_operation, init_db, list_operations, log_operation
from uavsec.keys import derive_keys, load_master_key
from uavsec.pipeline import decode, encode

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".mp4", ".mov", ".avi"}
_FILES: dict[str, tuple[Path, str]] = {}

def _load_startup_state() -> None:
	"""Initialize storage and load the master key once per process startup."""
	init_db()
	try:
		app.state.master_key = load_master_key()
		app.state.master_key_error = None
	except ValueError as error:
		app.state.master_key = None
		app.state.master_key_error = str(error)


@asynccontextmanager
async def lifespan(application: FastAPI):
	"""Initialize service state for the application lifetime."""
	_load_startup_state()
	yield


app = FastAPI(title="UAV Metadata Security", lifespan=lifespan)

def _master_key() -> bytes:
	"""Return the startup key or raise a service configuration error."""
	if not hasattr(app.state, "master_key"):
		_load_startup_state()
	if app.state.master_key is None:
		raise HTTPException(status_code=503, detail=app.state.master_key_error)
	return app.state.master_key

def _validate_upload(upload: UploadFile, allow_srt: bool = False) -> str:
	"""Validate an uploaded filename and return its lowercase extension."""
	if not upload.filename:
		raise HTTPException(status_code=400, detail="Uploaded file must have a filename")
	extension = Path(upload.filename).suffix.lower()
	allowed_extensions = ALLOWED_EXTENSIONS | ({".srt"} if allow_srt else set())
	if extension not in allowed_extensions:
		raise HTTPException(status_code=415, detail="Unsupported file type")
	return extension

async def _save_upload(
	upload: UploadFile, suffix: str | None = None, allow_srt: bool = False
) -> Path:
	"""Save an upload under the size limit and return its temporary path."""
	_validate_upload(upload, allow_srt)
	file_suffix = suffix or Path(upload.filename or "upload.bin").suffix.lower()
	temporary = tempfile.NamedTemporaryFile(delete=False, suffix=file_suffix)
	try:
		size = 0
		while chunk := await upload.read(1024 * 1024):
			size += len(chunk)
			if size > MAX_UPLOAD_BYTES:
				raise HTTPException(status_code=413, detail="Uploaded file exceeds 25 MiB limit")
			temporary.write(chunk)
		temporary.close()
		return Path(temporary.name)
	except Exception:
		temporary.close()
		Path(temporary.name).unlink(missing_ok=True)
		raise

def _keys(mission_id: str):
	"""Derive mission keys from the startup master key."""
	return derive_keys(_master_key(), mission_id)

def _file_id(path: Path, media_type: str) -> str:
	"""Register a downloadable file and return its opaque id."""
	identifier = uuid.uuid4().hex
	_FILES[identifier] = (path, media_type)
	return identifier

def _json_encode_result(result, operation_id: int) -> dict:
	"""Build the public encode response."""
	return {
		"operation_id": operation_id,
		"download_id": _file_id(result.stego_path, "image/png"),
		"cover_hash": result.cover_hash,
		"metadata": result.metadata,
		"payload_bytes": len(result.payload_bytes),
		"capacity_bits": result.capacity_bits,
		"psnr": result.psnr,
		"ssim": result.ssim,
		"trace": result.trace,
	}

@app.get("/health")
def health() -> dict[str, str]:
	"""Report service readiness and key configuration."""
	if not hasattr(app.state, "master_key"):
		_load_startup_state()
	return {"status": "ok" if app.state.master_key is not None else "degraded"}

@app.post("/encode")
async def encode_route(
	file: UploadFile = File(...),
	mission_id: str = Form(...),
	frame_index: Optional[int] = Form(None),
	srt: Optional[UploadFile] = File(None),
) -> dict:
	"""Encode an uploaded image or video and return its download id."""
	started = time.perf_counter()
	source_path: Optional[Path] = None
	srt_path: Optional[Path] = None
	try:
		extension = _validate_upload(file)
		source_path = await _save_upload(file, extension)
		if srt is not None:
			if Path(srt.filename or "").suffix.lower() != ".srt":
				raise HTTPException(status_code=415, detail="SRT upload must use .srt extension")
			srt_path = await _save_upload(srt, ".srt", allow_srt=True)
		out_path = Path(tempfile.mkdtemp(prefix="uavsec-output-")) / "stego.png"
		result = encode(source_path, _keys(mission_id), mission_id, srt_path, frame_index, out_path)
		operation_id = log_operation(
			"encode", mission_id, file.filename or "upload", result.cover_hash,
			len(result.payload_bytes), result.capacity_bits, result.psnr, result.ssim,
			(time.perf_counter() - started) * 1000, "AUTHENTIC", result.trace,
		)
		return _json_encode_result(result, operation_id)
	except HTTPException:
		raise
	except Exception as error:
		raise HTTPException(status_code=400, detail=f"Encode failed: {error}") from error
	finally:
		for path in (source_path, srt_path):
			if path is not None:
				path.unlink(missing_ok=True)

@app.post("/decode")
async def decode_route(
	file: UploadFile = File(...), mission_id: str = Form(...)
) -> dict:
	"""Decode an uploaded stego image and return verdict and restored image id."""
	started = time.perf_counter()
	path: Optional[Path] = None
	try:
		path = await _save_upload(file)
		result = decode(path, _keys(mission_id), mission_id)
		restored_id = None
		if result.restored_image is not None:
			temporary = Path(tempfile.mkdtemp(prefix="uavsec-restored-")) / "restored.png"
			save_stripped_png(result.restored_image, temporary)
			restored_id = _file_id(temporary, "image/png")
		operation_id = log_operation(
			"decode", mission_id, file.filename or "upload", None, None, None, None, None,
			(time.perf_counter() - started) * 1000, result.verdict, result.trace,
		)
		return {
			"operation_id": operation_id,
			"verdict": result.verdict,
			"metadata": result.metadata,
			"restored_image_id": restored_id,
			"cover_hash_match": result.cover_hash_match,
			"trace": result.trace,
		}
	except HTTPException:
		raise
	except Exception as error:
		raise HTTPException(status_code=400, detail=f"Decode failed: {error}") from error
	finally:
		if path is not None:
			path.unlink(missing_ok=True)

@app.post("/attack")
async def attack_route(
	file: UploadFile = File(...), attack_type: str = Form(...)
) -> dict[str, str]:
	"""Apply one deterministic image attack and return its PNG download id."""
	path: Optional[Path] = None
	try:
		path = await _save_upload(file)
		with Image.open(path) as image:
			image = image.convert("RGB")
			pixels = np.array(image)
			if attack_type == "pixel_flip":
				pixels[pixels.shape[0] // 2, pixels.shape[1] // 2, 0] ^= 1
				attacked = Image.fromarray(pixels)
			elif attack_type == "jpeg":
				buffer = io.BytesIO()
				image.save(buffer, format="JPEG", quality=45)
				attacked = Image.open(io.BytesIO(buffer.getvalue())).convert("RGB")
			elif attack_type == "crop_pad":
				width, height = image.size
				cropped = image.crop((1, 1, max(2, width - 1), max(2, height - 1)))
				attacked = cropped.resize((width, height), Image.Resampling.NEAREST)
			elif attack_type == "noise":
				noise = np.random.default_rng(7).integers(-3, 4, pixels.shape)
				attacked = Image.fromarray(np.clip(pixels.astype(np.int16) + noise, 0, 255).astype(np.uint8))
			else:
				raise HTTPException(status_code=400, detail="Unknown attack type")
			output = Path(tempfile.mkdtemp(prefix="uavsec-attack-")) / "attacked.png"
			attacked.save(output, format="PNG", exif=b"")
		return {"download_id": _file_id(output, "image/png")}
	except HTTPException:
		raise
	except Exception as error:
		raise HTTPException(status_code=400, detail=f"Attack failed: {error}") from error
	finally:
		if path is not None:
			path.unlink(missing_ok=True)

@app.get("/files/{file_id}")
def files_route(file_id: str) -> FileResponse:
	"""Return a registered stego, attacked, or restored image."""
	file_info = _FILES.get(file_id)
	if file_info is None or not file_info[0].exists():
		raise HTTPException(status_code=404, detail="File not found")
	return FileResponse(file_info[0], media_type=file_info[1], filename=file_info[0].name)

@app.get("/operations")
def operations_route(
	limit: int = Query(50, ge=1, le=1000), mission_id: Optional[str] = None
) -> list[dict]:
	"""List recent logged operations."""
	return list_operations(limit, mission_id)

@app.get("/operations/{operation_id}")
def operation_route(operation_id: int) -> dict:
	"""Return one logged operation."""
	operation = get_operation(operation_id)
	if operation is None:
		raise HTTPException(status_code=404, detail="Operation not found")
	return operation
