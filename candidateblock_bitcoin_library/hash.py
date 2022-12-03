# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""Bitcoin specific Hashs

Bitcoin has some specific routines for Hashing data this class
provides those
"""

import hashlib
from typing import Tuple

import candidateblock_bitcoin_library.base58 as base58

from .address_prefix import AddressPrefix

__all__ = ['bitcoin_address', 'double_sha256']


def double_sha256(s_hex: str) -> Tuple[str, str]:
    """Compute the 'double-SHA256' and checksum.

    Input hex string is coverted to byte array then hashed with
    Secure Hash Algorithm (SHA), specifically the 256-Bit (32-byte) version,
    twice resutling in 256-Bit (32-byte) double hash.
    Checksum is the first 32-Bit (4-byte, 8-Hex digits) of result

    Args:
        s_hex: Hex number as a string

    Returns:
        (double_sha256_hex string , check_sum string)
    """
    first_sha256 = hashlib.sha256(bytes.fromhex(s_hex))
    second_sha256 = hashlib.sha256(first_sha256.digest())
    s_double_sha256_hex = second_sha256.hexdigest()
    check_sum = s_double_sha256_hex[:8]
    return s_double_sha256_hex, check_sum


def hash160(s_hex: str) -> str:
    """Compute the 'Double Hash' or 'HASH160'.

    Input hex string is coverted to byte array then
    1. Hashed with SHA256 resutling in 256-Bit (32-byte) hash
    2. The result is hashed with RACE Integrity Primitives Evaluation Message Digest (RIPEMD)
       specifically the 160-bit version, (RIPEMD160) resulting in 160-bit (20-Byte)

    Args:
        s_hex: Hex number as a string

    Returns:
        bitcoin_address_hex as string
    """
    # 256-byte hash = 32-Bytes = 64 Hex Chars
    key_sha256 = hashlib.new("sha256", bytes.fromhex(s_hex)).digest()
    # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
    key_ripemd160 = hashlib.new("ripemd160", key_sha256).digest()
    bitcoin_address_hex = key_ripemd160.hex()
    return bitcoin_address_hex


def bitcoin_address(input_key_hex: str) -> str:
    """Encode a hex string to a Base58 Bitcoin address

    Take the input hex string and convert to Base58 Bitcoin address
    via a hash160 then convert hex string to Base58

    Args:
        s_hex: Hex number as a string

    Returns:
        Base58 encoded string
    """
    bitcoin_address_hex = hash160(s_hex=input_key_hex)
    return base58.b58check_encode(s_hex=bitcoin_address_hex, version_prefix=AddressPrefix.PUBKEY_HASH_ADDRESS.value)
