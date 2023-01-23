# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

# https://iancoleman.io/bip39/
# https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki Mnemonic code for generating deterministic keys

import hashlib
import os

from .mnem_bip39_word_list import bip39_english


class Mnemonic(object):
    """Mnemonic Class

    A mnemonic sentence (“mnemonic code”, “seed phrase”, “seed words”) is a
    way of representing a large randomly-generated number as a sequence of
    words, making it easier for humans to store
    BIP-39 defines the method
    """

    @classmethod
    def _generate_entropy(self, num_bytes: int) -> bytes:
        """_generate_entropy

        Collect entropy_bits of random data from the OS's cryptographically secure
        random number generator of length num_bytes

        Args:
            num_bytes (int): Number of bytes in the random number

        Returns:
            bytes: cryptographically secure random number
        """

        entropy = os.urandom(num_bytes)
        return entropy

    @classmethod
    def _words_to_bits(self, words: int) -> tuple:
        """_words_to_bits

        The following formula describes the relation between the initial
        entropy length (ENT), the checksum length (CS), and the length
        of the generated mnemonic sentence (MS) in words.

        CS [checksum_bits] = ENT / 32

        MS [mnemonic_sentence] = (ENT + CS) / 11

        ENT [entropy_bits] = CS - MS  (ENT is 128-256 bits)

        Args:
            words (int): Number of words only valid values 12, 15, 18, 21 or 24

        Returns:
            A tuple containing, respectively, an int (entropy_bits) and
            an int (entropy_and_checksum_bits) and
            an int (checksum_bits).
        """
        if words not in (12, 15, 18, 21, 24):
            raise ValueError('words argument can only be 12, 15, 18, 21 or 24')

        entropy_and_checksum_bits = int(words * 11)
        checksum_bits = int(entropy_and_checksum_bits / 33)
        entropy_bits = entropy_and_checksum_bits - checksum_bits

        return (entropy_bits, entropy_and_checksum_bits, checksum_bits)

    @classmethod
    def encode(self, entropy: bytes, words: int) -> str:
        """encode

        Mnemonic words are generated automatically by the wallet using the
        standardized process defined in BIP-39.

        Input a random sequence (entropy) of 128 to 256 bits.
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
        if len(entropy) not in (16, 20, 24, 28, 32):
            raise ValueError('entropy argument can only be 16, 20, 24, 28 or 32 bytes')

        entropy_bits, entropy_checksum_bits, checksum_bits = self._words_to_bits(
            words=words)
        # SHA-256 of entropy AS padded HEX STRING not integer
        entropy_sha256 = hashlib.sha256(entropy).digest()
        entropy_sha256_int = int.from_bytes(
            entropy_sha256, byteorder='big', signed=False)

        # Check sum first x bits of resulting SHA-256 of entropy
        # sha256_checksum_int = number of bits from 256 - checksum_bits
        sha256_checksum_int = entropy_sha256_int >> (256 - checksum_bits)

        # SHA-256 Checksum bits are added to end of orginal entropy
        entropy_int = int.from_bytes(bytes=entropy, byteorder='big', signed=False)
        entropy_and_checksum_int = entropy_int << checksum_bits
        entropy_and_checksum_int |= sha256_checksum_int

        # Each word is indexed by 11-bits, 11^2=2048 (0-2047), need to split and reverse order
        eleven_bits = 0b11111111111
        word_array = []
        for x in range(words):
            word_index = entropy_and_checksum_int & eleven_bits
            word_array.append(bip39_english[word_index])
            entropy_and_checksum_int = entropy_and_checksum_int >> 11
        word_array.reverse()
        bip39_mnemonic = ' '.join(word_array)
        return bip39_mnemonic

    @classmethod
    def decode(self, bip39_mnemonic: str) -> bytes:
        """decode

        For each word in the  bip39 mnemonic sentence, convert to its 11-Bit numberic value and
        logic shift the bits in to the correct integer place. Verify the checksum is valid.

        Args:
            str: A string storing Mnemonic 12-24 words

        Returns:
            bytes: entropy (orginal entropy, a cryptographically secure random number)
        """
        word_array = bip39_mnemonic.split()
        words = len(word_array)
        entropy_bits, entropy_checksum_bits, checksum_bits = self._words_to_bits(
            words=words)
        entropy_and_checksum_int = 0
        for word in word_array:
            index = bip39_english.index(word)
            entropy_and_checksum_int = entropy_and_checksum_int << 11
            entropy_and_checksum_int = entropy_and_checksum_int | index

        entropy_int = entropy_and_checksum_int >> checksum_bits
        sha256_checksum_bit_mask = (2 ** checksum_bits) - 1
        sha256_checksum_int = entropy_and_checksum_int & sha256_checksum_bit_mask

        # SHA-256 of entropy AS padded HEX STRING not integer
        entropy = entropy_int.to_bytes(length=int(
            entropy_bits / 8), byteorder='big', signed=False)
        entropy_sha256 = hashlib.sha256(entropy).digest()
        entropy_sha256_int = int.from_bytes(
            entropy_sha256, byteorder='big', signed=False)

        # Check sum first x bits of resulting SHA-256 of entropy
        # sha256_checksum_int = number of bits from 256 - checksum_bits
        new_sha256_checksum_int = entropy_sha256_int >> (256 - checksum_bits)

        if new_sha256_checksum_int != sha256_checksum_int:
            raise ValueError('Checksum error')

        return entropy_int.to_bytes(length=int(entropy_bits / 8), byteorder='big', signed=False)

    @classmethod
    def generate_mnemonic(self, words: int) -> str:
        """generate_mnemonic

        Mnemonic words are generated automatically by the wallet using the
        standardized process defined in BIP-39.

        Create a random sequence (entropy) of 128 to 256 bits.
        Generate the mnemonic sentence (a sequence of 12-24 words).

        Args:
            words (int): Number of words only valid values 12, 15, 18, 21 or 24

        Returns:
            str: A string storing Mnemonic 12-24 words
        """
        entropy_bits, entropy_checksum_bits, checksum_bits = self._words_to_bits(
            words=words)
        entropy_bytes = int(entropy_bits / 8)
        entropy = Mnemonic._generate_entropy(num_bytes=entropy_bytes)
        mnemonic_sentence = Mnemonic.encode(entropy=entropy, words=words)
        return mnemonic_sentence
