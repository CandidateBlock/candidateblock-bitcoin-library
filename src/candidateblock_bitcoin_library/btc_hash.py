# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""Bitcoin Specific Hashs

Bitcoin has some specific routines for Hashing data this class
provides those
"""

import hashlib
import hmac


class BtcHash(object):

    @staticmethod
    def sha256(value: bytes) -> bytes:
        """Compute the 'SHA256'

        Input bytes string is coverted to byte array then hashed with
        Secure Hash Algorithm (SHA), specifically the 256-Bit (32-byte) version,

        Args:
            value (bytes): bytes to be hashed

        Returns:
            bytes: SHA256 256-Bits, 32-Bytes
        """
        return hashlib.sha256(value).digest()

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
            Tuple: (double-SHA256 32-Bytes, check_sum 4-Bytes)
        """
        first_sha256 = BtcHash.sha256(value)
        second_sha256 = BtcHash.sha256(first_sha256)
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
            bytes: hash160 160-Bits, 20-Bytes
        """
        # 256-byte (32-Byte) hash
        value_sha256 = BtcHash.sha256(value)
        # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
        value_ripemd160 = hashlib.new("ripemd160", value_sha256).digest()
        return value_ripemd160

    @staticmethod
    def hmac_sha512(key: bytes, msg: bytes) -> bytes:
        """Compute the HMAC-SHA512 HMAC (Keyed-Hashing for Message Authentication)

        Input hex string is coverted to byte array then
        1. Hashed with SHA256 resutling in 256-Bit (32-byte) hash
        2. The result is hashed with RACE Integrity Primitives Evaluation Message Digest (RIPEMD)
        specifically the 160-bit version, (RIPEMD160) resulting in 160-bit (20-Byte)

        Args:
            key (bytes): bytes to be hash
            msg (bytes): bytes to be hash

        Returns:
            bytes: hash512 512-Bits, 64-Bytes
        """
        hmac_sha512 = hmac.new(key=key, msg=msg, digestmod=hashlib.sha512).digest()
        return hmac_sha512

    @staticmethod
    def pbkdf2_hmac(password: bytes, salt: bytes) -> bytes:
        """pbkdf2_hmac

        The PBKDF2 function is used to 'stretch' passwords with 2048 rounds.
        The iteration count is set to 2048 and HMAC-SHA512 is used as the
        pseudo-random function. The length of the result is 512 bits (64 bytes).

        Args:
            password (bytes): bytes to be pbkdf2_hmac streched
            salt (bytes): bytes to be pbkdf2_hmac streched

        Returns:
            bytes: 512-Bits, 64-Bytes
        """
        stretched_bytes = hashlib.pbkdf2_hmac(
            hash_name="sha512",
            password=password,
            salt=salt,
            iterations=2048
        )
        return stretched_bytes[:64]
