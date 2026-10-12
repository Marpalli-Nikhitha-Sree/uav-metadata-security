PROJECT: Securing Mission-Critical UAV Metadata Through AES Encryption, SSA-Based Shuffling, and Reversible Data Hiding.

STACK (use only these): Python 3.11, NumPy, opencv-python-headless, Pillow, PyExifTool, cryptography, hashlib, cbor2, scikit-image, Matplotlib, FastAPI + uvicorn + python-multipart, Streamlit + requests, sqlite3 (stdlib), pytest. Aletheia is called as an external CLI only.

ENCODER (UAV / companion computer):
1. Capture: image file, or keyframe from video (OpenCV).
2. Cover Preprocessor: decode to an 8-bit pixel array (grayscale HxW or RGB HxWx3; drop alpha, convert anything else to RGB). H(cover) = SHA-256 over shape + raw pixel bytes.
3. Metadata Extractor: EXIF + XMP via PyExifTool; SRT telemetry for video.
4. Filter + Serializer: keep whitelisted fields only, add H(cover), serialize to canonical CBOR.
5. AES-256-GCM with K_enc, random 12-byte nonce. Output = nonce || ciphertext || tag.
6. SSA Shuffler: keyed bit permutation with K_shuf.
7. RDH Embedder: prediction-error expansion + histogram shifting, pixel visiting order keyed by K_loc.
8. Output: PNG with all metadata headers stripped.

DECODER (ground station): RDH extract (bits out + image restored) -> inverse shuffle -> AES-GCM decrypt and verify tag -> binding check SHA-256(restored) == H(cover) from metadata -> original image (bit-exact) + metadata JSON + verdict.

KEY MANAGER: HKDF-SHA256 from one 32-byte master key, salt = mission_id, info labels "uav-rdh/enc", "uav-rdh/shuf", "uav-rdh/loc" -> K_enc, K_shuf, K_loc (32 bytes each).

VERDICTS: AUTHENTIC, TAMPERED_PAYLOAD (extraction or GCM failure), BINDING_MISMATCH (hash differs).

RULES:
- Every pipeline stage returns its result plus a trace entry {stage, summary, duration_ms, data_preview} so the UI can show every step.
- Type hints and short docstrings everywhere. No dead code, no placeholder functions, no TODOs, no unused imports or dependencies, no features outside this spec.
- All pixel arithmetic in int32, cast back to uint8 only at the end.
- Custom exceptions in one file: CapacityError, ExtractionError, AuthenticationError.
- Each step ends with pytest tests that must pass before you stop.
LAYOUT:
uavsec/ (config.py, errors.py, keys.py, capture.py, cover.py, metadata.py, serializer.py, crypto.py, shuffler.py, rdh.py, pipeline.py, metrics.py, steganalysis.py, db.py)
api/main.py, ui/app.py, scripts/ (evaluate.py, benchmark_pi.py), tests/, data/, outputs/
