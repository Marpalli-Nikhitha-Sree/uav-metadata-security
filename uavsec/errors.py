"""Exceptions shared by the UAV metadata security pipeline."""


class CapacityError(Exception):
	"""Raised when a cover cannot hold the encrypted payload."""


class ExtractionError(Exception):
	"""Raised when a payload cannot be extracted from a stego image."""


class AuthenticationError(Exception):
	"""Raised when encrypted metadata fails authentication."""
