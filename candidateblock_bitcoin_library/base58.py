# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""Base58 encoding.

Base58 and Base58Check encoding and decodings that are compatible
with the bitcoin network.
"""

# https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
# https://en.bitcoin.it/wiki/Base58Check_encoding
# https://learnmeabitcoin.com/technical/base58

import re

import candidateblock_bitcoin_library.hash as hash

__all__ = ['b58encode', 'b58decode',
           'b58encode_check', 'b58decode_check']

# All alphanumeric characters except for "0", "I", "O", and "l"
_b58alphabet: str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(s_hex: str) -> str:
    """Encode a hex string using Base58

    Take the input hex string and convert to Base58 using the
    Bitcoin alphabet, including leading 0x00's coverted to '1's

    Args:
        s_hex (str): Hex number

    Returns:
        str: Base58 encoded
    """
    global _b58alphabet
    s_base58: str = ""
    # Check if string empty
    if s_hex is None or s_hex == "":
        return s_base58

    # Process the hex string
    i: int = int(s_hex, 16)  # Convert hex string to integer
    while i != 0:
        floor, modulo = divmod(i, 58)
        # Reversed string
        s_base58 = _b58alphabet[modulo] + s_base58
        i = floor

    # To ensure that leading zeros have an influence on the result,
    # the bitcoin base58 encoding includes a manual step to convert all leading 0x00’s to 1’s
    i = 0
    while s_hex[i:i + 2] == "00":
        # _base58_alphabet[0] = "1"
        s_base58 = _b58alphabet[0] + s_base58
        i += 2
    return s_base58


def b58decode(s_base58: str) -> str:
    """Decode the Base58 encoded string

    Check s_base58 string is valid, remove padding.
    A ValueError is raised if s_base58 has invalid chars
    Decode Base58 into hex string, even char pad with '0' and
    with any leading '00'

    Args:
        s_base58 (str): Base58 encoded string

    Raises:
        ValueError: string argument should contain only Base58 characters

    Returns:
        str: Hex string
    """
    global _b58alphabet
    s_hex: str = ""
    if s_base58 is None or s_base58 == "":
        return s_hex

    # Skip leading spaces & other spacing chars
    s_base58 = s_base58.strip(" \t\n\v\f\r")

    # Check if string only contains allowed characters
    no_leading_zeros = s_base58.strip("0")
    if re.findall(f"[^{_b58alphabet}]", no_leading_zeros):
        raise ValueError('string argument should contain only Base58 characters')

    # Skip and count leading '1's.
    # the bitcoin base58 encoding includes a manual step to convert all leading 0x00’s to 1’s
    zeroes = len(s_base58) - len(s_base58.lstrip("1"))

    base10: int = 0
    index: int = 0
    # Reverse the input string
    s_base58 = s_base58[::-1]
    while len(s_base58) > 0:
        char = s_base58[0]
        value = _b58alphabet.index(char) * (58 ** index)
        base10 += value
        s_base58 = s_base58[1:]
        index += 1
    if base10 != 0:
        s_hex = hex(base10)[2:]  # Remove 0x from hex function
        # Check correct number of digits eg 3 should be 03, always even number
        if len(s_hex) % 2:
            s_hex = "0" + s_hex  # Make even chars with 0 padding
    # Add leading zeros back to s_hex sting
    s_hex = "00" * zeroes + s_hex
    return s_hex


def b58encode_check(s_hex: str, version_prefix: str) -> str:
    """Encode a hex string using Base58Check

    Base58Check
    1. Takes input hex string
    2. Appends a version prefix
    3. Computes the double-SHA256 checksum (4-Bytes) and appends to end
    4. Base58 encodes result

    Args:
        s_hex (str): Hex number as a string
        version_prefix (str): Identifier for type of data encoded as a string

    Returns:
        str: Base58Check encoded string
    """
    data = version_prefix + s_hex
    double_sha256_hex, checksum = hash.double_sha256(s_hex=data)
    full_hex = data + checksum
    return b58encode(s_hex=full_hex)


def b58decode_check(s_hex: str, version_prefix: str) -> str:
    """_summary_

    Args:
        s_hex (str): _description_
        version_prefix (str): _description_

    Returns:
        str: _description_
    """
    pass
