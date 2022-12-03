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
import os

from .bip39_word_list import bip39_english

# https://iancoleman.io/bip39/


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
        self.mnemonic = None

    def generate_mnemonic(self, words: int) -> str:
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
        if words not in (12, 15, 18, 21, 24):
            raise ValueError('words argument can only be 12, 15, 18, 21 or 24')

        mnemonic_lookup = {
            12: {"entropy_bits": 128, "checksum_bits": 4, "total_bits": 132},
            15: {"entropy_bits": 160, "checksum_bits": 5, "total_bits": 165},
            18: {"entropy_bits": 192, "checksum_bits": 6, "total_bits": 198},
            21: {"entropy_bits": 224, "checksum_bits": 7, "total_bits": 231},
            24: {"entropy_bits": 256, "checksum_bits": 8, "total_bits": 264},
        }
        entropy_bits = mnemonic_lookup[words].get('entropy_bits')
        checksum_bits = mnemonic_lookup[words].get('checksum_bits')
        entropy_bytes = int(entropy_bits / 8)
        entropy_hex_chars = int(entropy_bytes * 2)

        # Collect entropy_bits of random data from the OS's cryptographically secure
        # random number generator
        entropy_byte_array = os.urandom(entropy_bytes)
        entropy_int = int.from_bytes(entropy_byte_array, byteorder='big', signed=False)
        entropy_hex = f'{entropy_int:0{entropy_hex_chars}x}'
        # entropy_hex = 'e2f1772c6b50a0c3cc0764068d012b1581de5131411b0deb293d3eb026026da9'
        # entropy_int = int(entropy_hex, 16)
        # print(f'entropy_byte_array: {entropy_byte_array}')
        # print(f'entropy_int: {entropy_int} [{entropy_int.bit_length()}]')
        print(f'entropy_hex: {entropy_hex} ({len(entropy_hex)})')

        # SHA-256 of entropy AS padded HEX STRING not integer
        entropy_sha256_byte_array = hashlib.sha256(bytes.fromhex(entropy_hex)).digest()
        entropy_sha256_int = int.from_bytes(
            entropy_sha256_byte_array, byteorder='big', signed=False)

        # Check sum first x bits of resulting SHA-256 of entropy
        # sha256_checksum_int = number of bits from 256 - checksum_bits
        sha256_checksum_int = entropy_sha256_int >> (256 - checksum_bits)

        # SHA-256 Checksum bits are added to end of orginal entropy
        entropy_checksum_int = entropy_int << checksum_bits
        entropy_checksum_int |= sha256_checksum_int

        # Each word is indexed by 11-bits = 2048 (0-2046), need to split and reverse order
        eleven_bits = 0b11111111111
        word_array = []
        for x in range(words):
            word_index = entropy_checksum_int & eleven_bits
            word_array.append(bip39_english[word_index])
            entropy_checksum_int = entropy_checksum_int >> 11
        word_array.reverse()
        bip39_mnemonic = ' '.join(word_array)
        print(bip39_mnemonic)
