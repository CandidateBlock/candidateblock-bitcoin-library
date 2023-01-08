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
from .btc_hash import BtcHash


class Base58(object):
    # All alphanumeric characters except for "0", "I", "O", and "l"
    _b58alphabet: str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    @classmethod
    def encode(self, input: bytes = b'') -> str:
        """Encode bytes into a string using Base58

        Take the input bytes and convert to Base58 using the
        Bitcoin alphabet, including leading 0x00's coverted to '1's

        Args:
            input (bytes): value in bytes

        Returns:
            str: Base58 encoded
        """
        # Check if bytes empty
        if input is None or input == b'':
            raise ValueError('Input bytes can not be empty')

        base58 = ""
        num = int.from_bytes(bytes=input, byteorder='big', signed=False)
        while num != 0:
            floor, modulo = divmod(num, 58)
            # Reversed string
            base58 = self._b58alphabet[modulo] + base58
            num = floor

        # To ensure that leading zeros have an influence on the result,
        # the bitcoin base58 encoding includes a manual step to convert all leading zeros to string "1"
        for i in input:
            if i != 0:
                break
            base58 = self._b58alphabet[0] + base58

        return base58

    @classmethod
    def decode(self, base58: str) -> bytes:
        """Decode the Base58 encoded string

        Check base58 string is valid, remove padding.
        A ValueError is raised if base58 has invalid chars
        Decode Base58 into bytes, even char pad with '0' and
        with any leading '00'

        Args:
            base58 (str): Base58 encoded string

        Raises:
            ValueError: Input string can not be empty
            ValueError: string argument should contain only Base58 characters

        Returns:
            bytes: value in bytes
        """
        if base58 is None or base58 == "":
            raise ValueError('base58 string argument is empty')

        # Skip leading spaces & other spacing chars
        base58 = base58.strip(" \t\n\v\f\r")

        # Check if string only contains allowed characters
        no_leading_zeros = base58.strip("0")
        if re.findall(f"[^{self._b58alphabet}]", no_leading_zeros):
            raise ValueError(
                'base58 string argument should contain only Base58 characters')

        # Skip and count leading '1's.
        # the bitcoin base58 encoding includes a manual step to convert all leading 0x00’s to 1’s
        zeroes = len(base58) - len(base58.lstrip("1"))

        # Reverse the input string
        base58 = base58[::-1]
        value = 0
        for i, x in enumerate(base58):
            value += self._b58alphabet.index(x) * (58 ** i)

        num_bytes = 0
        if value != 0:
            chars = len(hex(value)[2:])  # Remove 0x from hex function
            # Check correct number of digits eg 3 should be 03, always even number
            if chars % 2:
                chars += 1
            num_bytes = int(chars / 2)

        num_bytes += zeroes
        return value.to_bytes(num_bytes, 'big')

    @classmethod
    def check_encode(self, payload: bytes = b'') -> str:
        """Encode a hex string using Base58Check

        Base58Check
        1. Takes input bytes payload
        2. Computes the double-SHA256 checksum (4-Byte) and appends to end
        3. Base58 encodes result

        Args:
            payload (bytes): value in bytes

        Returns:
            str: Base58Check encoded paload & (4-Byte) checksum
        """
        # Check if payload bytes empty
        if payload is None or payload == b'':
            raise ValueError('Input payload (bytes) can not be empty')

        # Calcuate checksum
        double_hash, check_sum = BtcHash.double_sha256(value=payload)
        raw_bytes = payload + check_sum
        return Base58.encode(input=raw_bytes)

    # @staticmethod
    # def check_encode(s_hex: str, version_prefix: str) -> str:
    #     """Encode a hex string using Base58Check

    #     Base58Check
    #     1. Takes input hex string
    #     2. Appends a version prefix
    #     3. Computes the double-SHA256 checksum (4-Bytes) and appends to end
    #     4. Base58 encodes result

    #     Args:
    #         s_hex (str): Hex number as a string
    #         version_prefix (str): Identifier for type of data encoded as a string

    #     Returns:
    #         str: Base58Check encoded string
    #     """
    #     data = version_prefix + s_hex
    #     double_sha256_hex, checksum = Hash.double_sha256(s_hex=data)
    #     full_hex = data + checksum
    #     return Base58.encode(s_hex=full_hex)

    # @staticmethod
    # def check_decode(s_base58: str) -> dict:
    #     """_summary_

    #     Args:
    #         s_base58 (str): Base58Check encoded string

    #     Returns:
    #         dict: checksum (hex str), payload (hex str), version (hex str)
    #     """
    #     # Char len 76 => Compressed, 74 => Not Compressed
    #     # 2-Bytes for prefix
    #     # 64-Bytes for Payload (256-Bit [64-Byte[] key)
    #     # 2-Bytes for compressed (optional)
    #     # 8-Bytes for checksum
    #     raw_hex = Base58.decode(s_base58=s_base58)
    #     checksum = raw_hex[-8:]
    #     # prefix is usually 1-Byte except xpub, xprv, tpub, tprv, bc1, tb1
    #     first_byte = raw_hex[:2]
    #     if first_byte != "04":
    #         prefix_byte_char_len = 2
    #     else:
    #         prefix_byte_char_len = 8
    #     prefix = raw_hex[:prefix_byte_char_len]
    #     payload = raw_hex[prefix_byte_char_len:-8]
    #     # Verify checksum
    #     double_sha256_hex, new_checksum = Hash.double_sha256(s_hex=prefix + payload)
    #     data = {"b58check": s_base58,
    #             "checksum": checksum,
    #             "checksum_match": new_checksum == checksum,
    #             "hex": raw_hex,
    #             "payload": payload,
    #             "prefix": prefix,
    #             }
    #     return data
