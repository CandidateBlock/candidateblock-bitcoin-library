# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""Bitcoin Wallets
The word “wallet” refers to the data structure used to store and
manage a users keys. In a sense the "wallet" is just a keychain.
We will only implement industry-standard-based hierarchical
deterministic (HD BIP-32/BIP-44) wallet with a
mnemonic seed (BIP-39) for backup.
"""

import hashlib
import hmac
import os

from .prefix import Prefix
from .base58 import Base58
from .bip39_word_list import bip39_english
from .keys import Keys

# https://iancoleman.io/bip39/
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki Hierarchical Deterministic Wallets
# https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki Mnemonic code for generating deterministic keys
# https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki Multi-Account Hierarchy for Deterministic Wallets


class Wallet(object):
    """Wallet Class

    The word “wallet” refers to the data structure used to store and
    manage a users keys. In a sense the "wallet" is just a keychain.
    We will only implement industry-standard-based hierarchical
    deterministic (HD BIP-32/BIP-44) wallet with a
    mnemonic seed (BIP-39) for backup.

    Attributes:
        mnemonic: A string storing Mnemonic 12-24 words

    """

    def __init__(self) -> None:
        """Inits Keys with known state.
        """
        self.bip39_mnemonic = None
        self.entropy_int = None

    def _generate_entropy(self, num_bytes: int) -> int:
        # Collect entropy_bits of random data from the OS's cryptographically secure
        # random number generator
        entropy_byte_array = os.urandom(num_bytes)
        entropy_int = int.from_bytes(entropy_byte_array, byteorder='big', signed=False)
        return entropy_int

    def bip39_mnemonic_encode(self, entropy_int: int, words: int) -> str:
        self.bip39_mnemonic = None
        self.entropy_int = entropy_int
        # ENT [entropy_bits] / 32 - ENT is 128-256 bits
        # CS [checksum_bits] = ENT / 32
        # MS [mnemonic_sentence] = (ENT + CS) / 11
        mnemonic_sentence = words
        entropy_checsum_bits = int(mnemonic_sentence * 11)
        checksum_bits = int(entropy_checsum_bits / 33)
        entropy_bits = entropy_checsum_bits - checksum_bits
        entropy_bytes = int(entropy_bits / 8)
        entropy_hex_chars = int(entropy_bytes * 2)
        entropy_hex = f'{entropy_int:0{entropy_hex_chars}x}'
        print(f'entropy_int: {entropy_int} [{entropy_int.bit_length()}]')
        print(f'entropy_hex: {entropy_hex} ({len(entropy_hex)})')

        # bytes.fromhex() the string must contain two hexadecimal digits per byte
        if len(entropy_hex) % 2 != 0:
            entropy_hex = '0' + entropy_hex
        # SHA-256 of entropy AS padded HEX STRING not integer
        entropy_sha256_byte_array = hashlib.sha256(bytes.fromhex(entropy_hex)).digest()
        entropy_sha256_int = int.from_bytes(
            entropy_sha256_byte_array, byteorder='big', signed=False)

        # Check sum first x bits of resulting SHA-256 of entropy
        # sha256_checksum_int = number of bits from 256 - checksum_bits
        sha256_checksum_int = entropy_sha256_int >> (256 - checksum_bits)
        print(f'sha256_checksum_int hex: {sha256_checksum_int:x}')
        print(f'sha256_checksum_int bin: {sha256_checksum_int:0{checksum_bits}b}')

        # SHA-256 Checksum bits are added to end of orginal entropy
        entropy_checksum_int = entropy_int << checksum_bits
        entropy_checksum_int |= sha256_checksum_int
        print(f'entropy_checksum_int: {entropy_checksum_int}')
        print(f'entropy_checksum_int hex: {entropy_checksum_int:x}')

        # Each word is indexed by 11-bits, 11^2=2048 (0-2047), need to split and reverse order
        eleven_bits = 0b11111111111
        word_array = []
        for x in range(words):
            word_index = entropy_checksum_int & eleven_bits
            word_array.append(bip39_english[word_index])
            entropy_checksum_int = entropy_checksum_int >> 11
        word_array.reverse()
        self.bip39_mnemonic = ' '.join(word_array)
        return self.bip39_mnemonic

    def bip39_mnemonic_decode(self, bip39_mnemonic: str) -> int:
        self.bip39_mnemonic = None
        self.entropy_int = None
        word_array = bip39_mnemonic.split()
        words = len(word_array)
        if words not in (12, 15, 18, 21, 24):
            raise ValueError('words argument can only be 12, 15, 18, 21 or 24')
        self.bip39_mnemonic = bip39_mnemonic
        entropy_checksum_int = 0
        # ENT / 32
        # CS = ENT / 32
        # MS = (ENT + CS) / 11
        mnemonic_sentence = words
        entropy_checsum_bits = int(mnemonic_sentence * 11)
        checksum_bits = int(entropy_checsum_bits / 33)
        entropy_bits = entropy_checsum_bits - checksum_bits

        for word in word_array:
            index = bip39_english.index(word)
            entropy_checksum_int = entropy_checksum_int << 11
            entropy_checksum_int = entropy_checksum_int | index
        # remove checksum 4-bits
        print(
            f'entropy_checksum_int: {entropy_checksum_int} [{entropy_checksum_int.bit_length()}]')
        entropy_checksum_hex = f'{entropy_checksum_int:x}'
        print(
            f'entropy_checksum_hex: {entropy_checksum_hex} ({len(entropy_checksum_hex)})')
        entropy_int = entropy_checksum_int >> checksum_bits
        sha256_checksum_bit_mask = (2 ** checksum_bits) - 1
        sha256_checksum_int = entropy_checksum_int & sha256_checksum_bit_mask
        print(f'sha256_checksum_int hex: {sha256_checksum_int:x}')
        print(f'sha256_checksum_int bin: {sha256_checksum_int:0{checksum_bits}b}')
        print(f'entropy_int: {entropy_int} [{entropy_int.bit_length()}]')
        num_hex_chars = int(entropy_bits / 8) * 2
        entropy_hex = f'{entropy_int:0{num_hex_chars}x}'
        print(f'entropy_hex: {entropy_hex} ({len(entropy_hex)})')
        self.entropy_int = entropy_int
        return entropy_int

    def bip39_generate_mnemonic(self, words: int) -> None:
        """Mnemonic words are generated automatically by the wallet using the
        standardized process defined in BIP-39.

        Create a random sequence (entropy) of 128 to 256 bits.
        Create a checksum of the random sequence by taking the first (entropy-length/32) bits of its SHA256 hash.
        Add the checksum to the end of the random sequence.
        Split the result into 11-bit length segments.
        Map each 11-bit value to a word from the predefined dictionary of 2048 words.
        The mnemonic code is the sequence of words.

        Args:
            words (int): Number of words only valid values 12, 15, 18, 21 or 24

        Returns:
            str: A string storing Mnemonic 12-24 words
        """
        self.bip39_mnemonic = None
        if words not in (12, 15, 18, 21, 24):
            raise ValueError('words argument can only be 12, 15, 18, 21 or 24')

        # ENT [entropy_bits] / 32 - ENT is 128-256 bits
        # CS [checksum_bits] = ENT / 32
        # MS [mnemonic_sentence] = (ENT + CS) / 11
        mnemonic_sentence = words
        entropy_checsum_bits = int(mnemonic_sentence * 11)
        checksum_bits = int(entropy_checsum_bits / 33)
        entropy_bits = entropy_checsum_bits - checksum_bits
        entropy_bytes = int(entropy_bits / 8)
        entropy_int = self._generate_entropy(num_bytes=entropy_bytes)
        mnemonic_sentence = self.bip39_mnemonic_encode(
            entropy_int=entropy_int, words=words)
        return mnemonic_sentence

    def bip39_mnemonic_to_root_seed(self, mnemonic_sentence: str, passphrase: str = "") -> bytes:
        """Mnemonic words are generated automatically by the wallet using the
        standardized process defined in BIP-39.

        Create a random sequence (entropy) of 128 to 256 bits.
        Create a checksum of the random sequence by taking the first (entropy-length/32) bits of its SHA256 hash.
        Add the checksum to the end of the random sequence.
        Split the result into 11-bit length segments.
        Map each 11-bit value to a word from the predefined dictionary of 2048 words.
        The mnemonic code is the sequence of words.

        Args:
            words (int): Number of words only valid values 12, 15, 18, 21 or 24

        Returns:
            str: A string storing Mnemonic 12-24 words
        """
        passphrase = 'mnemonic' + passphrase
        mnemonic_bytes = mnemonic_sentence.encode('utf-8')
        passphrase_bytes = passphrase.encode('utf-8')
        stretched_bytes = hashlib.pbkdf2_hmac(
            hash_name="sha512",
            password=mnemonic_bytes,
            salt=passphrase_bytes,
            iterations=2048
        )
        return stretched_bytes[:64]
        # return stretched[:64]

        # mnemonic_salt_sha256_byte_array = hashlib.sha512(
        #     mnemonic_salt.encode('utf8')).digest()
        # rounds = 2048 - 2
        # pbkdf2 = mnemonic_salt_sha256_byte_array
        # for r in range(rounds):
        #     pbkdf2 = hashlib.sha512(pbkdf2).digest()
        # hashlib.pbkdf2_hmac(hash_name='sha512', password=)
        # seed_512_bit_hex = pbkdf2.hex()
        # print(f'seed_512_bit_hex: {seed_512_bit_hex}')
        # return seed_512_bit_hex

    # BIP-32 Hierarchical Deterministic Wallets
    @staticmethod
    def bip32_master_key_generation(seed: bytes):
        seed_hmac_sha512 = hmac.new(key=b"Bitcoin seed", msg=seed,
                                    digestmod=hashlib.sha512).digest()
        master_private_key = seed_hmac_sha512[:32]  # Left 256-bits
        master_chain_code = seed_hmac_sha512[32:]   # Right 256-bits
        # xprv = b"\x00" * 9  # Depth 1-byte, parent fingerprint 4-bytes, and child number 4-bytes
        # Depth 1-byte
        xprv = int(0).to_bytes(length=1, byteorder='big', signed=False)
        # parent fingerprint 4-bytes
        xprv += int(0).to_bytes(length=4, byteorder='big', signed=False)
        # child number 4-bytes
        xprv += int(0).to_bytes(length=4, byteorder='big', signed=False)
        xprv += master_chain_code
        xprv += b"\x00" + master_private_key
        xprv_hex = xprv.hex()
        xprv_base58 = Base58.check_encode(
            s_hex=xprv_hex, version_prefix=Prefix.BIP_32_EXTENDED_PRIVATE_KEY)
        print(f'xprv_base58: {xprv_base58}')

    @ staticmethod
    def bip32_child_key_derivation(parent_key: bytes,
                                   parent_chaincode: bytes,
                                   depth: int,
                                   index: int,
                                   is_private: bool):
        """Mnemonic words are generated automatically by the wallet using the
        standardized process defined in BIP-39.

        Create a random sequence (entropy) of 128 to 256 bits.
        Create a checksum of the random sequence by taking the first (entropy-length/32) bits of its SHA256 hash.
        Add the checksum to the end of the random sequence.
        Split the result into 11-bit length segments.
        Map each 11-bit value to a word from the predefined dictionary of 2048 words.
        The mnemonic code is the sequence of words.

        Args:
            words (int): Number of words only valid values 12, 15, 18, 21 or 24

        Returns:
            str: A string storing Mnemonic 12-24 words
        """

        # Is this a public or private parent key
        if is_private:
            parent_priv_key = parent_key
            keys = Keys()
            keys.private_key = int.from_bytes(
                bytes=parent_priv_key, byteorder='big', signed=False)
            keys.generate_public_key()
            parent_pub_key = bytes.fromhex(keys.get_public_key_compressed_hex())
        else:
            parent_priv_key = None
            parent_pub_key = parent_key

        # Is the child a hardened key
        if index >= 2**31:
            #  = HMAC - SHA512(Key=cpar, Data=0x00 | | ser256(kpar) | | ser32(i)). ()
            if not is_private:
                raise Exception("Can't do private derivation on public key!")
            # Note: The 0x00 pads the PRIVATE key to make it 33 bytes long.
            hash_input = b"\x00"
            hash_input += parent_priv_key
            hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
            hmac_sha512 = hmac.new(key=parent_chaincode,
                                   msg=hash_input,
                                   digestmod=hashlib.sha512).digest()
        else:
            # Note: COMPRESSED PUBLIC key is 33 bytes long
            hash_input = parent_pub_key
            hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
            hmac_sha512 = hmac.new(key=parent_chaincode,
                                   msg=hash_input,
                                   digestmod=hashlib.sha512).digest()
        if is_private:
            child_chaincode = hmac_sha512[32:]  # Right 256-bits
            # PRIVATE child key
            child_private_key = hmac_sha512[:32]    # Left 256-bits
            parent_private_key_int = int.from_bytes(
                bytes=parent_priv_key, byteorder='big', signed=False)
            child_private_key_int = int.from_bytes(
                bytes=child_private_key, byteorder='big', signed=False)
            n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            child_private_key_int = int(
                (child_private_key_int + parent_private_key_int) % n)
            child_private_key = child_private_key_int.to_bytes(
                length=32, byteorder='big', signed=False)
            # Get parent PUBLIC key fingerprint
            # 256-byte hash = 32-Bytes = 64 Hex Chars
            key_sha256 = hashlib.new("sha256", parent_pub_key).digest()
            # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
            key_ripemd160 = hashlib.new("ripemd160", key_sha256).digest()
            parent_key_fingerprint = key_ripemd160[:4]    # first 32-bits 4-bytes
        else:
            pass

        xprv = int(depth).to_bytes(length=1, byteorder='big', signed=False)
        xprv += parent_key_fingerprint
        xprv += index.to_bytes(length=4, byteorder='big', signed=False)
        xprv += child_chaincode
        xprv += b"\x00" + child_private_key
        xprv_base58 = Base58.check_encode(
            s_hex=xprv.hex(), version_prefix=Prefix.BIP_32_EXTENDED_PRIVATE_KEY)
        print(f'xprv_base58: {xprv_base58}')
