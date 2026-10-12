"""Streamlit dashboard for the UAV metadata security API."""

from __future__ import annotations

import io
import csv
import json
import os
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import requests
import streamlit as st
from PIL import Image


API_URL = os.getenv("UAVSEC_API_URL", "http://127.0.0.1:8000").rstrip("/")
PAGE_NAMES = ["Overview", "Encoder (UAV)", "Decoder (Ground Station)", "Attack Lab", "Evaluation", "History"]


def _request(method: str, path: str, **kwargs: Any) -> requests.Response | None:
	"""Call the backend and show a friendly connection or HTTP error."""
	try:
		response = requests.request(method, f"{API_URL}{path}", timeout=60, **kwargs)
	except requests.RequestException as error:
		st.error(f"Backend unavailable at {API_URL}: {error}")
		return None
	if not response.ok:
		try:
			detail = response.json().get("detail", response.text)
		except ValueError:
			detail = response.text
		st.error(f"Backend returned HTTP {response.status_code}: {detail}")
		return None
	return response


def _download(file_id: str) -> bytes | None:
	"""Download a backend-managed file by id."""
	response = _request("GET", f"/files/{file_id}")
	return response.content if response is not None else None


def _show_trace(trace: list[dict[str, Any]], label: str = "Pipeline trace") -> None:
	"""Render every trace stage as an ordered expandable step."""
	st.subheader(label)
	for index, entry in enumerate(trace, start=1):
		stage = entry.get("stage", "stage")
		duration = float(entry.get("duration_ms", 0))
		with st.expander(f"{index:02d}  {stage}  ·  {duration:.2f} ms", expanded=False):
			st.caption(entry.get("summary", ""))
			st.json(entry.get("data_preview", {}), expanded=False)


def _image(data: bytes) -> np.ndarray:
	"""Decode downloaded image bytes for dashboard visualizations."""
	return np.array(Image.open(io.BytesIO(data)).convert("RGB"))


def _image_panel(title: str, data: bytes) -> None:
	"""Display an image with a compact caption."""
	st.image(data, caption=title, use_container_width=True)


def _metadata_table(metadata: dict[str, Any] | None) -> None:
	"""Render normalized metadata as a two-column table."""
	if not metadata:
		st.info("No metadata recovered.")
		return
	rows = [{"field": key, "value": value} for key, value in metadata.items()]
	st.dataframe(rows, hide_index=True, use_container_width=True)


def _hex_preview(value: Any, limit: int = 64) -> str:
	"""Format a trace hex preview with a bounded display length."""
	text = str(value or "")
	return text[:limit] + ("..." if len(text) > limit else "")


def _bits_plot(before: list[int], after: list[int]) -> None:
	"""Plot compact before/after bit rows."""
	figure, axis = plt.subplots(figsize=(12, 1.7))
	axis_before = np.arange(min(128, len(before)))
	axis_after = np.arange(min(128, len(after)))
	axis_before_values = np.asarray(before[: len(axis_before)], dtype=int)
	axis_after_values = np.asarray(after[: len(axis_after)], dtype=int)
	axis.scatter(axis_before, axis_before_values + 1.2, s=8, label="before")
	axis.scatter(axis_after, axis_after_values, s=8, label="after")
	axis.set_yticks([0, 1, 1.2, 2.2], ["0", "1", "0", "1"])
	axis.set_xlabel("bit index")
	axis.grid(axis="x", alpha=0.15)
	axis.legend(loc="upper right", ncol=2)
	st.pyplot(figure, use_container_width=True)
	plt.close(figure)


def _histogram_panel(cover: np.ndarray, stego: np.ndarray) -> None:
	"""Render before/after pixel histograms."""
	figure, axis = plt.subplots(figsize=(10, 3.2))
	axis.hist(cover.reshape(-1), bins=256, range=(0, 255), alpha=0.55, label="cover")
	axis.hist(stego.reshape(-1), bins=256, range=(0, 255), alpha=0.55, label="stego")
	axis.set_xlabel("pixel value")
	axis.set_ylabel("count")
	axis.legend()
	axis.grid(alpha=0.15)
	st.pyplot(figure, use_container_width=True)
	plt.close(figure)


def _render_encoder_details(result: dict[str, Any], source: bytes, stego: bytes) -> None:
	"""Render the encoder trace, diagnostics, and downloads."""
	trace = result.get("trace", [])
	_show_trace(trace, "Encoder stages")
	metadata_entry = next((entry for entry in trace if entry.get("stage") == "metadata"), {})
	metadata_preview = metadata_entry.get("data_preview", {})
	st.subheader("Metadata filtering")
	left, right = st.columns(2)
	with left:
		st.caption("Extracted metadata")
		_metadata_table(metadata_preview.get("raw", {}))
	with right:
		st.caption("Whitelisted metadata")
		_metadata_table(metadata_preview.get("filtered", {}))
		dropped = sorted(set(metadata_preview.get("raw", {})) - set(metadata_preview.get("filtered", {})))
		if dropped:
			st.caption(f"Dropped fields: {', '.join(dropped)}")
	cover_entry = next((entry for entry in trace if entry.get("stage") == "cover"), {})
	serialize_entry = next((entry for entry in trace if entry.get("stage") == "serialize"), {})
	encrypt_entry = next((entry for entry in trace if entry.get("stage") == "encrypt"), {})
	shuffle_entry = next((entry for entry in trace if entry.get("stage") == "shuffle"), {})
	embed_entry = next((entry for entry in trace if entry.get("stage") == "embed"), {})
	st.subheader("Cryptographic and RDH diagnostics")
	st.code(f"Cover SHA-256\n{cover_entry.get('data_preview', result.get('cover_hash', ''))}")
	st.caption("Canonical CBOR, first 64 bytes")
	st.code(_hex_preview(serialize_entry.get("data_preview"), 128))
	st.caption("AES-GCM nonce || ciphertext || tag")
	st.code(_hex_preview(encrypt_entry.get("data_preview"), 160))
	shuffle_preview = shuffle_entry.get("data_preview", {})
	if isinstance(shuffle_preview, dict) and "before" in shuffle_preview:
		_bits_plot(shuffle_preview["before"], shuffle_preview.get("after", []))
	else:
		st.caption("Shuffled bit preview unavailable from this backend version.")
	st.json(embed_entry.get("data_preview", {}), expanded=False)
	cover_array = _image(source)
	stego_array = _image(stego)
	st.subheader("Visual forensics")
	first, second = st.columns(2)
	with first:
		_image_panel("Cover", source)
	with second:
		_image_panel("Stego", stego)
	difference = np.abs(stego_array.astype(np.int16) - cover_array.astype(np.int16)).astype(np.uint8)
	amplified = np.clip(difference.astype(np.int16) * 32, 0, 255).astype(np.uint8)
	st.image(amplified, caption="Amplified absolute difference ×32", use_container_width=True)
	_histogram_panel(cover_array, stego_array)
	metrics = st.columns(3)
	metrics[0].metric("PSNR", "∞" if result.get("psnr") == float("inf") else f"{result.get('psnr', 0):.2f} dB")
	metrics[1].metric("SSIM", f"{result.get('ssim', 0):.5f}")
	metrics[2].metric("Payload", f"{result.get('payload_bytes', 0)} bytes")
	st.download_button("Download stego PNG", stego, "stego.png", "image/png", use_container_width=True)


def _overview() -> None:
	"""Render the project architecture overview."""
	st.title("UAV Metadata Security")
	st.caption("Mission-critical metadata protection with authenticated, reversible embedding")
	status = _request("GET", "/health")
	if status is not None:
		st.success("Backend online" if status.json().get("status") == "ok" else "Backend degraded")
	st.subheader("Encoder / decoder architecture")
	modules = [
		("Capture", "Image or video keyframe"),
		("Cover", "Normalize pixels and bind SHA-256"),
		("Metadata", "EXIF, XMP, and SRT telemetry"),
		("Serializer", "Whitelist and canonical CBOR"),
		("Crypto", "AES-256-GCM authentication"),
		("SSA shuffle", "Keyed bit permutation"),
		("RDH", "Prediction-error reversible embedding"),
		("Ground station", "Extract, verify, restore"),
	]
	for index, (name, detail) in enumerate(modules):
		st.markdown(
			f"<div class='architecture-row'><strong>{index + 1:02d} · {name}</strong><span>{detail}</span></div>",
			unsafe_allow_html=True,
		)


def _encoder() -> None:
	"""Render the UAV encoder workflow."""
	st.title("Encoder · UAV")
	upload = st.file_uploader("Source image or video", type=["png", "jpg", "jpeg", "mp4", "mov", "avi"], key="encoder_upload")
	srt = st.file_uploader("Optional DJI SRT telemetry", type=["srt"], key="encoder_srt")
	mission_id = st.text_input("Mission ID", value=st.session_state.get("mission_id", "mission-7"))
	frame_index = st.slider("Frame index", 0, 10000, 0) if upload and Path(upload.name).suffix.lower() in {".mp4", ".mov", ".avi"} else None
	if st.button("Run encoder", type="primary", disabled=upload is None):
		files = {"file": (upload.name, upload.getvalue(), upload.type or "application/octet-stream")}
		if srt is not None:
			files["srt"] = (srt.name, srt.getvalue(), "application/x-subrip")
		data = {"mission_id": mission_id}
		if frame_index is not None:
			data["frame_index"] = str(frame_index)
		response = _request("POST", "/encode", files=files, data=data)
		if response is not None:
			result = response.json()
			st.session_state["encode_result"] = result
			st.session_state["mission_id"] = mission_id
			st.session_state["stego_bytes"] = _download(result["download_id"])
			st.session_state["source_bytes"] = upload.getvalue()
			st.rerun()
	result = st.session_state.get("encode_result")
	if result and st.session_state.get("stego_bytes") and st.session_state.get("source_bytes"):
		_render_encoder_details(result, st.session_state["source_bytes"], st.session_state["stego_bytes"])


def _decoder() -> None:
	"""Render the ground-station decoder workflow."""
	st.title("Decoder · Ground Station")
	upload = st.file_uploader("Stego PNG", type=["png", "jpg", "jpeg"], key="decoder_upload")
	mission_id = st.text_input("Mission ID", value=st.session_state.get("mission_id", "mission-7"), key="decoder_mission")
	if st.button("Run decoder", type="primary", disabled=upload is None):
		response = _request(
			"POST", "/decode", files={"file": (upload.name, upload.getvalue(), upload.type or "image/png")}, data={"mission_id": mission_id}
		)
		if response is not None:
			result = response.json()
			st.session_state["decode_result"] = result
			if result.get("restored_image_id"):
				st.session_state["restored_bytes"] = _download(result["restored_image_id"])
			st.rerun()
	result = st.session_state.get("decode_result")
	if not result:
		return
	verdict = result.get("verdict", "UNKNOWN")
	color = {"AUTHENTIC": "#16805c", "BINDING_MISMATCH": "#b97900", "TAMPERED_PAYLOAD": "#b42318"}.get(verdict, "#475467")
	st.markdown(f"<div class='verdict' style='background:{color}'>{verdict}</div>", unsafe_allow_html=True)
	_show_trace(result.get("trace", []), "Decoder stages")
	st.subheader("Recovered metadata")
	_metadata_table(result.get("metadata"))
	if result.get("metadata"):
		st.download_button("Download metadata JSON", json.dumps(result["metadata"], indent=2), "metadata.json", "application/json")
	metadata = result.get("metadata") or {}
	if metadata.get("gps_lat") is not None and metadata.get("gps_lon") is not None:
		st.map({"lat": [metadata["gps_lat"]], "lon": [metadata["gps_lon"]]}, zoom=12)
	restored = st.session_state.get("restored_bytes")
	if restored:
		st.subheader("Restored image")
		st.image(restored, use_container_width=True)
		if result.get("cover_hash_match"):
			st.success("✓ Bit-exact match")
		st.download_button("Download restored image", restored, "restored.png", "image/png")


def _attack_lab() -> None:
	"""Render attack and re-verification controls."""
	st.title("Attack Lab")
	st.caption("Apply a controlled transformation to the latest stego image, then send it back through the decoder.")
	stego = st.session_state.get("stego_bytes")
	mission_id = st.session_state.get("mission_id", "mission-7")
	if not stego:
		st.info("Run the Encoder first to create a stego image.")
		return
	attack_type = st.selectbox("Attack", ["pixel_flip", "jpeg", "crop_pad", "noise"])
	if st.button("Apply attack and decode", type="primary"):
		attack = _request("POST", "/attack", files={"file": ("stego.png", stego, "image/png")}, data={"attack_type": attack_type})
		if attack is not None:
			attacked = _download(attack.json()["download_id"])
			if attacked:
				st.session_state["attacked_bytes"] = attacked
				decoded = _request("POST", "/decode", files={"file": ("attacked.png", attacked, "image/png")}, data={"mission_id": mission_id})
				if decoded is not None:
					st.session_state["attack_result"] = decoded.json()
	result = st.session_state.get("attack_result")
	if result:
		verdict = result.get("verdict", "UNKNOWN")
		st.error(f"Verdict: {verdict}") if verdict != "AUTHENTIC" else st.success("Attack was not detected")
		trace = result.get("trace", [])
		failed = next((entry for entry in trace if "failed" in entry.get("summary", "").lower()), None)
		if failed:
			st.info(f"Tampering caught at: {failed.get('stage')}")
		_show_trace(trace, "Attack decoder trace")
		if st.session_state.get("attacked_bytes"):
			st.image(st.session_state["attacked_bytes"], caption=f"Attacked image · {attack_type}", use_container_width=True)


def _evaluation() -> None:
	"""Render evaluation artifacts when scripts have produced them."""
	st.title("Evaluation")
	data_dir = Path("data")
	outputs_dir = Path("outputs")
	csv_files = sorted(list(data_dir.glob("*.csv")) + list(outputs_dir.glob("*.csv")))
	plot_files = sorted(list(data_dir.glob("*.png")) + list(outputs_dir.glob("*.png")))
	if not csv_files and not plot_files:
		st.info("No evaluation artifacts found. Generate them with `python scripts/evaluate.py`.")
		return
	for csv_file in csv_files:
		st.subheader(csv_file.name)
		with csv_file.open(newline="", encoding="utf-8") as handle:
			st.dataframe(list(csv.DictReader(handle)), use_container_width=True)
	for plot_file in plot_files:
		st.image(str(plot_file), caption=plot_file.name, use_container_width=True)


def _history() -> None:
	"""Render backend operation history and stored traces."""
	st.title("History")
	mission = st.text_input("Filter by mission ID", key="history_mission")
	params = {"limit": 100}
	if mission:
		params["mission_id"] = mission
	response = _request("GET", "/operations", params=params)
	if response is None:
		return
	operations = response.json()
	if not operations:
		st.info("No operations recorded yet.")
		return
	st.dataframe([{key: value for key, value in operation.items() if key != "trace"} for operation in operations], use_container_width=True)
	selected = st.selectbox("Operation detail", operations, format_func=lambda item: f"#{item['id']} · {item['kind']} · {item['mission_id']}")
	st.json(selected.get("trace", []), expanded=False)


def main() -> None:
	"""Render the dashboard shell and selected page."""
	st.set_page_config(page_title="UAV Metadata Security", page_icon="🛰️", layout="wide", initial_sidebar_state="expanded")
	st.markdown(
		"""
		<style>
		:root { --ink: #17212b; --muted: #64748b; --line: #d9e2ec; --accent: #075985; }
		.block-container { max-width: 1440px; padding-top: 2rem; }
		.architecture-row { display:flex; justify-content:space-between; gap:2rem; padding:.8rem 1rem; margin:.35rem 0; border-left:4px solid var(--accent); border-bottom:1px solid var(--line); color:var(--ink); }
		.architecture-row span { color:var(--muted); text-align:right; }
		.verdict { color:white; font-size:2rem; font-weight:700; letter-spacing:.04em; padding:1rem 1.25rem; border-radius:.5rem; margin:.75rem 0 1.5rem; text-align:center; }
		</style>
		""",
		 unsafe_allow_html=True,
	)
	with st.sidebar:
		st.markdown("## UAVSEC")
		st.caption("Mission metadata security console")
		page = st.radio("Navigate", PAGE_NAMES, label_visibility="collapsed")
		st.divider()
		st.caption(f"Backend\n{API_URL}")
	if page == "Overview":
		_overview()
	elif page == "Encoder (UAV)":
		_encoder()
	elif page == "Decoder (Ground Station)":
		_decoder()
	elif page == "Attack Lab":
		_attack_lab()
	elif page == "Evaluation":
		_evaluation()
	else:
		_history()


if __name__ == "__main__":
	main()
