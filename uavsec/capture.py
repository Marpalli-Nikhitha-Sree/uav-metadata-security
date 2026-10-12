"""Image and video capture helpers."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from uavsec.errors import ExtractionError


def _opencv() -> object:
	"""Import OpenCV lazily so non-video operations remain usable."""
	try:
		import cv2
	except ImportError as error:
		raise ExtractionError("OpenCV is required to load images or video keyframes") from error
	return cv2


def load_image(path: str | Path) -> np.ndarray:
	"""Load an image file and return it as an RGB uint8 array."""
	cv2 = _opencv()
	image = cv2.imread(str(path), cv2.IMREAD_COLOR)
	if image is None:
		raise ExtractionError(f"Unable to read image file: {path}")
	return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)


def extract_keyframe(video_path: str | Path, frame_index: int) -> np.ndarray:
	"""Extract a zero-based video frame and return it as an RGB uint8 array."""
	if frame_index < 0:
		raise ExtractionError("Frame index must be non-negative")
	cv2 = _opencv()
	capture = cv2.VideoCapture(str(video_path))
	if not capture.isOpened():
		capture.release()
		raise ExtractionError(f"Unable to open video file: {video_path}")
	try:
		frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
		if frame_count > 0 and frame_index >= frame_count:
			raise ExtractionError(
				f"Frame index {frame_index} is out of range for {video_path} "
				f"({frame_count} frames)"
			)
		capture.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
		read_ok, frame = capture.read()
		if not read_ok or frame is None:
			raise ExtractionError(f"Unable to read frame {frame_index} from {video_path}")
		return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
	finally:
		capture.release()
