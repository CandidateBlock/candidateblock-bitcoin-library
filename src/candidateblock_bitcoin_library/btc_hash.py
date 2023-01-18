# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""Bitcoin Specific Hashs

Bitcoin has some specific routines for Hashing data this class
provides those
"""

import hashlib


class BtcHash(object):

    @staticmethod
    def double_sha256(value: bytes) -> tuple[bytes, bytes]:
        """Compute the 'double-SHA256' and checksum.

        Input bytes string is coverted to byte array then hashed with
        Secure Hash Algorithm (SHA), specifically the 256-Bit (32-byte) version,
        twice resutling in 256-Bit (32-byte) double hash.
        Checksum is the first 32-Bit (4-byte) of result

        Args:
            value (bytes): bytes to be double hashed

        Returns:
            Tuple: (double-SHA256 32-bytes, check_sum 4-bytes)
        """
        first_sha256 = hashlib.sha256(value)
        second_sha256 = hashlib.sha256(first_sha256.digest()).digest()
        return second_sha256, second_sha256[:4]

    @staticmethod
    def hash160(value: bytes) -> bytes:
        """Compute the 'Double Hash' or 'HASH160'.

        Input hex string is coverted to byte array then
        1. Hashed with SHA256 resutling in 256-Bit (32-byte) hash
        2. The result is hashed with RACE Integrity Primitives Evaluation Message Digest (RIPEMD)
        specifically the 160-bit version, (RIPEMD160) resulting in 160-bit (20-Byte)

        Args:
            value (bytes): bytes to be hash160

        Returns:
            bytes: hash160 20-bytes
        """
        # 256-byte (32-Byte) hash
        value_sha256 = hashlib.new("sha256", value).digest()
        # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
        value_ripemd160 = hashlib.new("ripemd160", value_sha256).digest()
        return value_ripemd160
