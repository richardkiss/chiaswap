
# Based on this specification from Pieter Wuille:
# https://github.com/sipa/bips/blob/bip-bech32m/bip-bech32m.mediawiki
"""Reference implementation for Bech32m and segwit addresses."""

from chia_base.util.bech32 import bech32_decode, bech32_encode, convertbits, Encoding


def encode_puzzle_hash(puzzle_hash: bytes, prefix: str) -> str:
    encoded = bech32_encode(prefix, convertbits(puzzle_hash, 8, 5), Encoding.BECH32M)
    return encoded


def decode_puzzle_hash(address: str) -> bytes:
    hrpgot, data, spec = bech32_decode(address)
    if spec != Encoding.BECH32M or data is None:
        raise ValueError("Invalid Address")
    decoded = convertbits(data, 5, 8, False)
    decoded_bytes = bytes(decoded)
    return decoded_bytes
