# Copyright (c) 2023 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

from .base58 import Base58
from .hashes import Hashes
from .prefix import Prefix
from . import py_secp256k1


class Keys(object):
    """Bitcoin Private and Public Key Class

    Bitcoin has a Private Key (that should remain secret) and a
    Public Key that can be shared.
    A Private key is just a random 256-Bit (32-byte) number (with some size
    limitation due to discrete Elliptic Curve).
    A Public key is generated from a one way cryptographic function
    called secp256k1 which uses an Elliptic Curve.
    """

    # The secp256k1 curve is over a finite field of prime order p
    _p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
    # Number of points on secp256k1 curve
    _n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _a = 0x0000000000000000000000000000000000000000000000000000000000000000
    _b = 0x0000000000000000000000000000000000000000000000000000000000000007
    _r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

    # ************************************************************************************************************************
    # Private Key ************************************************************************************************************
    # ************************************************************************************************************************

    @staticmethod
    def _random_secret() -> bytes:
        """Generate a random number for use as Private Key

        Generate a cryptographically secure random number

        Returns:
            bytes: 256-Bit (32-Byte) cryptographically secure random number
        """

        # Collect 256-bits (32-bytes) of random data from the Operating Systems
        # cryptographically secure random number generator
        # return os.urandom(32)
        # Replaced with secp256k1 lib
        return py_secp256k1._key.generate_privkey()

    @classmethod
    def is_priv_key_valid(self, priv_key: bytes) -> bool:
        """Verify if Private Key Valid

        Check if number (containted in input bytes) is within the range
        limits of the Elliptic Curve which is defined over a finite field of
        prime order instead of over the real numbers

        Args:
            priv_key (bytes): private key 32-bytes, 256-bits

        Returns:
            bool: private key is valid
        """
        # priv_key_int = int.from_bytes(bytes=priv_key, byteorder='big', signed=False)
        # return 0 < priv_key_int < self._n
        # Replaced with secp256k1 lib
        return py_secp256k1.ec_seckey_verify(secret=priv_key, context=None)

    @classmethod
    def generate_priv_key(self) -> bytes:
        """Generate Private Key

        Generate a 256-Bit Private Key by using a cryptographically
        secure random number and checking valid over Elliptic Curve finite field

        Returns:
            bytes: Raw 256-bit (32-byte) Private Key = Random Number
        """
        # Generate a random private key
        # is_valid_priv_key = False
        # while not is_valid_priv_key:
        #     priv_key = self._random_secret()
        #     # Check with in bounds for Bitcoin > 0 and < n
        #     is_valid_priv_key = self.is_priv_key_valid(priv_key=priv_key)

        # return priv_key
        # Replaced with secp256k1 lib
        prv = py_secp256k1._key.ECKey()
        prv.generate(compressed=True)
        return prv.get_bytes()

    @classmethod
    def priv_key_wif_encode(self, priv_key: bytes = b'', is_compressed: bool = True, is_mainnet: bool = True) -> str:
        """Private Key encoded to 'Wallet Import Format' (Base58 Check)

        A WIF private key is a standard private key, but with a few added extras:
        1. Version Byte prefix - Indicates which network the private key is to be used on.
        2. Compression Byte suffix (optional)
        3. Checksum

        Args:
            priv_key (bytes): private key 32-bytes, 256-bits
            is_compressed (bool): Should this private key be used to generate compressed public keys
            is_mainnet (bool): Network for the private key to be used on (Mainnet or Testnet)

        Returns:
            str: Base58 Check encoded WIF Private Key
        """
        if is_mainnet:
            prefix = b'\x80'
        else:
            prefix = b'\xEF'

        if is_compressed:
            compressed = b'\x01'
        else:
            compressed = b''

        # Create the bytes with correct values & order
        raw_bytes = prefix
        raw_bytes += priv_key
        raw_bytes += compressed

        # Base58Check - includes 4-byte checksum
        return Base58.check_encode(payload=raw_bytes)

    @classmethod
    def priv_key_wif_decode(self, wif_b58: str = '') -> tuple:
        """Private Key 'Wallet Import Format' (Base58 Check) decoded to private key, compressed, network

        Decode Private key WIF back to constituent parts.
        Verify length, Base58 Check checksum and Version Byte Prefix for Mainnet or Testnet

        Args:
            wif_b58 (str): Base58 encoded WIF Private Key

        Returns:
            A tuple containing, respectively, a bytes (private key 32-bytes, 256-bits) and
            a bool (Should this private key be used to generate compressed public keys) and
            a bool (Network for the private key to be used on [Mainnet or Testnet]).
        """
        wif = Base58.decode(b58=wif_b58)

        # Check valid checksum
        payload = wif[:-4]
        checksum = wif[-4:]
        double_hash, new_check_sum = Hashes.double_sha256(value=payload)
        if new_check_sum != checksum:
            raise Exception("WIF checksum not correct")

        version = payload[0]
        payload = payload[1:]
        if version == 0x80:
            is_mainnet = True
        elif version == 0xEF:
            is_mainnet = False
        else:
            raise Exception(
                f"WIF version byte={payload[0].hex()} is not valid. 0x80 or 0xEF Valid")

        # Check if valid length. (32-bytes => WIF, 33-Bytes => WIF Compressed)
        if len(payload) == 32:
            is_compressed = False
            priv_key = payload
        elif len(payload) == 33:
            is_compressed = True
            priv_key = payload[:-1]  # Remove '\x01' compression byte from end
        else:
            raise Exception(
                f"WIF length incorrect {len(payload)}, valid is 32 or 33 bytes.")

        return (priv_key, is_compressed, is_mainnet)

    # ************************************************************************************************************************
    # Public Key *************************************************************************************************************
    # ************************************************************************************************************************
    @classmethod
    def generate_pub_key(self, priv_key: bytes = b'', is_compressed: bool = True) -> bytes:
        """Calculate Public key from the Private Key

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

        "Uncompressed" Public Key Format
        "\\x04" prefix (1-Byte) -> "Uncompressed"
        + X Coordinate as 256-Bit (32-Byte)
        + Y Coordinate as 256-Bit (32-Byte)
        result string = 520-Bit (65-Byte)

        "Compressed" Public Key Format
        "Compressed" means store x coordinate value and y coordinate sign
        "\\x02" prefix (1-Byte) if y is even
        "\\x03" prefix (1-Byte) if y is odd
        Even or Odd Hex prefix -> "Compressed"
        + X Coordinate as 256-Bit (32-Byte)
        result string = 264-Bit (33)
        This results in nearly a 50% size reduction compared to the
        "Uncompressed" Private Key size of 520-Bit (65-Bytes)
        264 / 520 = 50.8%


        Args:
            priv_key (bytes): private key 32-bytes, 256-bits
            is_compressed (bool): private key format

        Returns:
            bytes: Public key 32-bytes, 256-bits
        """
        # curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(self._p, self._a, self._b)
        # generator_secp256k1 = ecdsa.ellipticcurve.Point(
        #     curve_secp256k1, self._Gx, self._Gy, self._r)
        # priv_key_int = int.from_bytes(bytes=priv_key, byteorder='big', signed=False)
        # # Calculate the public key point (x, y)
        # pub_key_point = priv_key_int * generator_secp256k1
        # x_pt = int(pub_key_point.x()).to_bytes(length=32, byteorder='big', signed=False)
        # y_pt = int(pub_key_point.y()).to_bytes(length=32, byteorder='big', signed=False)
        # if not is_compressed:
        #     # "Uncompressed" Public Key Format
        #     # "\x04" prefix (1-Byte) -> "Uncompressed"
        #     # + X Coordinate as 256-Bit (32-Byte)
        #     # + Y Coordinate as 256-Bit (32-Byte)
        #     # result string = 520-Bit (65-Byte)
        #     pub_key = b'\04' + x_pt + y_pt
        # else:
        #     # "Compressed" Public Key Format
        #     # "Compressed" means store x coordinate value and y coordinate sign
        #     # "\x02" prefix (1-Byte) if y is even
        #     # "\x03" prefix (1-Byte) if y is odd
        #     # Even or Odd Hex prefix -> "Compressed"
        #     # + X Coordinate as 256-Bit (32-Byte)
        #     # result string = 264-Bit (33)
        #     # This results in nearly a 50% size reduction compared to the
        #     # "Uncompressed" Private Key size of 520-Bit (65-Bytes)
        #     # 264 / 520 = 50.8%
        #     if int.from_bytes(bytes=y_pt, byteorder='big', signed=False) % 2:
        #         # "\x03" prefix byte if y is odd
        #         pub_key = b'\x03' + x_pt
        #     else:
        #         # "\x02" prefix byte if y is even
        #         pub_key = b'\x02' + x_pt
        # return pub_key
        # Replaced with secp256k1 lib
        prv = py_secp256k1._key.ECKey()
        prv.set(secret=priv_key, compressed=is_compressed)
        return prv.get_pubkey().get_bytes()

    @classmethod
    def btc_address_p2pkh(self, pub_key: bytes = b'', is_mainnet: bool = True) -> str:
        """Convert the Public Key to a Pay To PubKey Hash (P2PKH) Bitcoin address

        The Public Key can be compressed (33-Bytes) or uncompressed (32-Bytes)
        it is hashed via HASH160 resulting in 160-Bits, 20-Bytes (a reduction)
        The result is prefixed with PayToPubKeyHash 0x00 and Base58Check encoded

        Args:
            pub_key (bytes): Public Key 32/33-bytes, 256/264-bits

        Returns:
            str: P2PKH Bitcoin address Base58Check encoded
        """
        hash160 = Hashes.hash160(value=pub_key)
        if is_mainnet:
            payload = Prefix.PAY_TO_PUBKEY_HASH + hash160
        else:
            payload = Prefix.TESTNET_PAY_TO_PUBKEY_HASH + hash160

        p2pkh_address = Base58.check_encode(payload=payload)
        return p2pkh_address
