"""Command-line interface for the UAV metadata security pipeline."""

from __future__ import annotations

import argparse

from uavsec.keys import derive_keys, generate_master_key
from uavsec.pipeline import decode, encode


def _keyset(master_hex: str, mission_id: str):
	"""Derive pipeline keys from a hexadecimal master key."""
	return derive_keys(bytes.fromhex(master_hex), mission_id)


def main() -> None:
	"""Run the encode, decode, or keygen command."""
	parser = argparse.ArgumentParser(prog="python -m uavsec")
	subparsers = parser.add_subparsers(dest="command", required=True)
	keygen = subparsers.add_parser("keygen")
	keygen.set_defaults(handler=lambda args: print(generate_master_key().hex()))
	encode_parser = subparsers.add_parser("encode")
	encode_parser.add_argument("source")
	encode_parser.add_argument("mission_id")
	encode_parser.add_argument("--master-key", required=True)
	encode_parser.add_argument("--out", default="outputs/stego.png")
	decode_parser = subparsers.add_parser("decode")
	decode_parser.add_argument("stego")
	decode_parser.add_argument("mission_id")
	decode_parser.add_argument("--master-key", required=True)
	args = parser.parse_args()
	if args.command == "keygen":
		args.handler(args)
		return
	keys = _keyset(args.master_key, args.mission_id)
	if args.command == "encode":
		result = encode(args.source, keys, args.mission_id, out_path=args.out)
		print(result.stego_path)
	else:
		result = decode(args.stego, keys, args.mission_id)
		print(result.verdict)


if __name__ == "__main__":
	main()