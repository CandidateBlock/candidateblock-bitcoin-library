# Copyright (c) 2023 CandidateBlock
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
from .hashes import Hashes


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
    def decode(self, b58: str = "") -> bytes:
        """Decode the Base58 encoded string

        Check base58 string is valid, remove padding.
        A ValueError is raised if base58 has invalid chars
        Decode Base58 into bytes, even char pad with '0' and
        with any leading '00'

        Args:
            b58 (str): Base58 encoded string

        Raises:
            ValueError: Input string can not be empty
            ValueError: string argument should contain only Base58 characters

        Returns:
            bytes: value in bytes
        """
        if b58 is None or b58 == "":
            raise ValueError('base58 string argument is empty')

        # Skip leading spaces & other spacing chars
        b58 = b58.strip(" \t\n\v\f\r")

        # Check if string only contains allowed characters
        no_leading_zeros = b58.strip("0")
        if re.findall(f"[^{self._b58alphabet}]", no_leading_zeros):
            raise ValueError(
                'base58 string argument should contain only Base58 characters')

        # Skip and count leading '1's.
        # the bitcoin base58 encoding includes a manual step to convert all leading 0x00’s to 1’s
        zeroes = len(b58) - len(b58.lstrip("1"))

        # Reverse the input string
        b58 = b58[::-1]
        value = 0
        for i, x in enumerate(b58):
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
        double_hash, check_sum = Hashes.double_sha256(value=payload)
        raw_bytes = payload + check_sum
        return Base58.encode(input=raw_bytes)

    @classmethod
    def check_decode(self, b58: str = "") -> tuple:
        """_summary_

        Args:
            b58 (str): Base58Check encoded string

        Raises:
            ValueError: Checksum not valid

        Returns:
            A tuple containing, respectively, a bytes (address prefix) and
            a bytes (payload) and
            a bytes (checksum)
        """
        # bytes len 38 => Compressed, 37 => Not Compressed
        # 1-Bytes for prefix
        # 32-Bytes for Payload (256-Bit [64-Bkey)
        # 1-Bytes for compressed (optional)
        # 4-Bytes for checksum
        raw_hex = Base58.decode(b58=b58)
        # prefix is usually 1-Byte except xpub, xprv, tpub, tprv, bc1, tb1
        first_byte = raw_hex[0]
        if first_byte == b'\04':
            prefix_byte_len = 4
        else:
            prefix_byte_len = 1

        prefix = raw_hex[:prefix_byte_len]
        payload = raw_hex[prefix_byte_len:-4]
        checksum = raw_hex[-4:]
        # Verify checksum
        double_sha256_hex, new_checksum = Hashes.double_sha256(value=prefix + payload)
        if not (new_checksum == checksum):
            raise ValueError('Checksum not valid')

        return (prefix, payload, checksum)
