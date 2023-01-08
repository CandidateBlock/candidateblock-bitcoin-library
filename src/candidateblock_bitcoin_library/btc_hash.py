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
        if len(s_hex) % 2 != 0:
            s_hex = '0' + s_hex
        # 256-byte hash = 32-Bytes = 64 Hex Chars
        key_sha256 = hashlib.new("sha256", bytes.fromhex(s_hex)).digest()
        # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
        key_ripemd160 = hashlib.new("ripemd160", key_sha256).digest()
        bitcoin_address_hex = key_ripemd160.hex()
        return bitcoin_address_hex
