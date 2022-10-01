# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import os

import ecdsa

import candidateblock_bitcoin_library.base58 as base58
import candidateblock_bitcoin_library.hash as hash

from .address_prefix import AddressPrefix


class Keys(object):
    """Bitcoin Private and Public Key Class

    Bitcoin has a Private Key (that should remain secret) and a
    Public Key that can be shared.
    A Private key is just a random 256-Bit number (with some size
    limitation due to discrete Elliptic Curve).
    A Public is generated from a one way cryptographic function
    called secp256k1 which uses an Elliptic Curve.

    Attributes:
        private_key: An integer storing Private key as 256-Bit number
        public_key: A point (x, y) on the Elliptic Curve

    """

    def __init__(self) -> None:
        """Inits Keys with known state.
        """
        self.private_key = None
        self.public_key = None

    @staticmethod
    def _hex256(input_hex: str) -> str:
        """Pad 256-Bit Hex sting to always be even number of chars

        256-Bit hex number should have 64 chars (256 / 4).
        4-Bits = 0-f in Hex.

        Args:
            input_hex (str): Hex number

        Returns:
            str: Base58 encoded
        """
        # 256 bit hex number should have 64 chars (256 / 4). 4 bits = 0-f in hex
        digits_missing = 64 - len(input_hex)
        output_hex = input_hex
        if digits_missing > 0:
            # Pad front of sting with "0"
            output_hex = "0" * digits_missing + output_hex
        return output_hex

    # ************************************************************************************************************************
    # Private Key ************************************************************************************************************
    # ************************************************************************************************************************

    @staticmethod
    def _random_secret() -> int:
        """Generate a random number for use as Private Key

        Generate a cryptographically secure random number

        Returns:
            int: 256-Bit Random Number
        """

        # Collect 256 bits of random data from the OS's cryptographically secure
        # random number generator
        byte_array = os.urandom(32)
        # Convert 32 bytes into hex string then back to integer (256 bits)
        return int(byte_array.hex(), 16)

    def generate_private_key(self) -> int:
        """Generate Private Key

        Generate a 256-Bit Private Key by using a cryptographically
        secure random number and limiting size to < p where p is a very
        large prime number. The Elliptic Curve is defined over a
        finite field of prime order instead of over the real numbers

        Returns:
            int: Raw 256-Bit (32-Byte) Private Key = Random Number
        """
        _p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
        # Generate a random private key
        valid_private_key = False
        while not valid_private_key:
            private_key = self._random_secret()
            # Check with in bounds for Bitcoin > 0 and < p
            valid_private_key = 0 < private_key < _p

        self.private_key = private_key
        return self.private_key

    def get_private_key(self) -> int:
        """Get Private Key

        Access method to private_key

        Returns:
            int: Raw 256-Bit (32-Byte) Private Key
        """
        return self.private_key

    def get_private_key_hex(self) -> str:
        """Get Private Key Hex

        Convert Private Key from 256-Bit integer to 64-Char Hex string
        with "0" padding. (Each Hex character holds 4-Bits, 256 / 4 = 64 Chars)

        Returns:
            str: 64-Byte Hex Private Key
        """
        hex_str = hex(self.private_key)[2:]  # remove 0x from Hex string
        # Return hex string 64 chars long => 256 bits, "0" padding
        return self._hex256(hex_str)

    def get_private_key_base58(self) -> str:
        """Get Private Key Base58

        Convert Private Key from 256-Bit integer to Base58
        encoded string

        Returns:
            str: Base58 encoded
        """
        return base58.b58encode(s_hex=self.get_private_key_hex())

    def get_private_key_wif(self) -> str:
        """Get Private Key WIF in "Uncompressed" Format

        Convert Private Key from 256-Bit integer to Base58 encoded
        string in Wallet Import Format (WIF).
        "Uncompressed" => PUBLIC keys generated from private key
        should be "Uncompressed".

        Uncompressed WIF

        Payload = Version Prefix (Number of Bytes varies)
        Payload = Payload + Private Key (64-Byte Hex Private Key)
        Hex = Hex + Checksum (first 4-Bytes of double_sha256 Payload)
        Base58 Encode Check (Hex) - leading char is "5"

        Returns:
            str: Base58 encoded
        """
        return base58.b58encode_check(s_hex=self.get_private_key_hex(), version_prefix=AddressPrefix.PRIVATE_KEY_WIF.value)

    def get_private_key_wif_compressed(self) -> str:
        """Get Private Key WIF in "Compressed" Format

        Convert Private Key from 256-Bit integer to Base58 encoded
        string in "Compressed" Wallet Import Format (WIF).
        "Compressed" => PUBLIC keys generated from private key should
        be in "Compressed" format.

        Compressed WIF

        Payload = Version Prefix (Number of Bytes varies)
        Payload = Payload + Private Key (64-Byte Hex Private Key)
        Payload = Payload + "01" (1-Byte Hex suffix added to Private Key)
        Hex = Hex + Checksum (4-Bytes of double_sha256 of Payload)
        Base58 Encode Check (Hex) - leading char is "K" or "L"

        Returns:
            str: Base58 encoded
        """
        return base58.b58encode_check(s_hex=self.get_private_key_hex() + "01", version_prefix=AddressPrefix.PRIVATE_KEY_WIF.value)

    def decode_private_key_wif_compressed(self, private_key_wif_b58check: str) -> bool:
        """_summary_

        Args:
            private_key_wif_b58check (str): _description_

        Returns:
            bool: _description_
        """
        # Char len 76 => Compressed, 74 => Not Compressed
        # 2 for prefix
        # 64 for 256-Bit key
        # 2 for compressed (optional)
        # 8 for checksum
        raw_hex = base58.b58decode(s_base58=private_key_wif_b58check)
        wif_hex = raw_hex
        prefix = wif_hex[:2]
        payload = wif_hex[2:-8]
        wif_hex = wif_hex[2:]
        pk = wif_hex[:64]
        wif_hex = wif_hex[64:]
        compressed = wif_hex[:2]
        wif_hex = wif_hex[2:]
        checksum = wif_hex
        # Verify checksum
        new_checksum = hash.double_sha256(s_hex=raw_hex[:-8])[:8]
        if new_checksum == checksum:
            print("matches")
        else:
            print("error")
        self.private_key = int(pk, 16)
        self.public_key = None
        data = {"base58": private_key_wif_b58check,
                "hex": raw_hex,
                "checksum": checksum,
                "prefix": prefix,
                "payload": payload,
                "compressed": compressed}
        return data

    # ************************************************************************************************************************
    # Public Key *************************************************************************************************************
    # ************************************************************************************************************************
    def generate_public_key(self) -> None:
        """Generate Public Key

        The public key is calculated from the private key using
        elliptic curve multiplication, which is irreversible:
        K = k * G, where k is the private key, G is a constant
        point called the generator point, and K is the resulting
        public key.

        The secp256k1 curve is defined by the following function,
        y^2 = (X^3 + 7) over Fp or
        Y^2 mod p = (x^3 +7) mod p
        The mod p (modulo prime number p) indicates that this curve is
        over a finite field of prime order p,
        where p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1,
        a very large prime number.

        """
        _p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        _r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        _b = 0x0000000000000000000000000000000000000000000000000000000000000007
        _a = 0x0000000000000000000000000000000000000000000000000000000000000000
        _Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        _Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
        generator_secp256k1 = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)
        # Calculate the public key point (x, y)
        self.public_key = self.private_key * generator_secp256k1

    def get_public_key(self) -> str:
        """Get Public Key point in raw number format

        The Public Key is a (x, y) point on the elliptic curve.
        Raw format is a string in the format "point x (int), point y (int)"

        Returns:
            str: "point x (int)" + "," + "point y (int)"
        """
        return str(self.public_key.x()) + "," + str(self.public_key.y())

    def get_public_key_hex(self) -> str:
        """Get Public Key "Uncompressed" (x, y) point as a Hex String

        Convert the Public Key (x, y) point to a Hex string.
        Each point coordinate is 256-Bit = 32-Byte = 64 Char Hex string

        "Uncompressed" Public Key Format

        Hex = "04" Hex prefix 8-Bit, 1-Byte, 2-Char Hex -> "Uncompressed"
        Hex = Hex + X Coordinate as 256-Bit, 32-Byte, 64-Char Hex
        Hex = Hex + Y Coordinate as 256-Bit, 32-Byte, 64-Char Hex
        Hex result string = 520-Bit, 65-Byte, 130-Char Hex

        Returns:
            str: "04" + "point x (Hex)" + "point y (Hex)"
        """
        x_hex = self._hex256(hex(self.public_key.x())[2:])
        y_hex = self._hex256(hex(self.public_key.y())[2:])
        return "04" + x_hex + y_hex

    def get_public_key_bitcoin_address(self) -> str:
        """Get Public Key "Uncompressed" (x, y) point as a Base58 String

        Take "Uncompressed" Public Key Hex string and convert to a
        Bitcoin address encoded in Base58

        Returns:
            str: Public Key "Uncompressed" as a Bitcoin address encoded in Base58
        """
        return hash.bitcoin_address(input_key_hex=self.get_public_key_hex())

    def get_public_key_compressed_hex(self) -> str:
        """Get Public Key "Compressed" (x, y) point as a Hex String

        A "Compressed" Public Key reduces the amount of bytes need
        versus the "Uncompressed" Public Key format.

        Note: The same Public Key can generate valid "Uncompressed" and
        "Compressed" Private Keys but the wallet software needs to know
        what type of address to scan the Blockchain for, either
        "Compressed" or "Uncompressed" but not both! Hence Public Key
        WIF and WIF-Compressed format to let wallet software know if
        it should be scaning the Blockchain for "Compressed" or
        "Uncompressed" Public Keys.

        This is acheived by taking advantage of the x-axis symmetry of
        the elliptic curve.

        You can calculate the y point on the elliptic curve if
        you have the x point and the sign of the y point by solving
        this equation y^2 mod p = (x^3 + 7) mod p.

        "Compressed" means store x coordinate value and y coordinate sign

        "Compressed" Public Key Format

        "02" Hex prefix 8-Bit, 1-Byte, 2-Char Hex byte if y is even
        "03" Hex prefix 8-Bit, 1-Byte, 2-Char Hex byte if y is odd

        Hex = Even or Odd Hex prefix -> "Compressed"
        Hex = Hex + X Coordinate as 256-Bit, 32-Byte, 64-Char Hex
        Hex result string = 264-Bit, 33-Byte, 66-Char Hex

        This results in nearly a 50% size reduction compared to the
        "Uncompressed" Private Key size of 520-Bit, 65-Byte, 130-Char Hex
        66 / 130 = 50.8%

        Returns:
            str: "02" or "03" + "point x (Hex)"
        """
        if self.public_key.y() % 2:
            # "03" prefix byte if y is odd
            return "03" + hex(self.public_key.x())[2:]
        else:
            # "02" prefix byte if y is even
            return "02" + hex(self.public_key.x())[2:]

    def get_public_compressed_key_base58check(self) -> str:
        """Get Public Key "Compressed" (x, y) point as a Base58 String

        Take "Compressed" Public Key Hex string and convert to a
        Bitcoin address encoded in Base58

        Returns:
            str: "Compressed" Public Key encoded in Base58
        """
        public_key_compressed_hex = self.get_public_key_compressed_hex()
        return base58.b58encode_check(public_key_compressed_hex, version_prefix=AddressPrefix.PUBKEY_HASH_ADDRESS.value)

    def get_public_compressed_key_bitcoin_address(self) -> str:
        """Get Public Key "Compressed" (x, y) point as a Base58 String

        Take "Compressed" Public Key Hex string and convert to a
        Bitcoin address encoded in Base58

        Returns:
            str: "Compressed" Public Key as Bitcoin address encoded in Base58
        """
        public_key_compressed_hex = self.get_public_key_compressed_hex()
        return hash.bitcoin_address(input_key_hex=public_key_compressed_hex)
