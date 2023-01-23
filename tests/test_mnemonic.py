# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import pytest

import candidateblock_bitcoin_library as cbl

priv_key = bytes.fromhex(
    '0ae377964b26eba86f992a59f1600f256b9afc6fc6de6980f0140b69aba51dd6')


class TestMnemonic:
    # **************************************************
    # Generate Entropy
    # **************************************************
    def test_mnemonic_generate_entropy_one(self):
        # Check random number returns correct length of bytes
        assert len(cbl.Mnemonic._generate_entropy(num_bytes=12)) == 12
        assert len(cbl.Mnemonic._generate_entropy(num_bytes=15)) == 15
        assert len(cbl.Mnemonic._generate_entropy(num_bytes=18)) == 18
        assert len(cbl.Mnemonic._generate_entropy(num_bytes=21)) == 21
        assert len(cbl.Mnemonic._generate_entropy(num_bytes=24)) == 24

    # **************************************************
    # Generate Encode
    # **************************************************
    def test_mnemonic_encode_one(self):
        # 12 Words use 16-Bytes, 128-Bit entropy
        entropy = bytes.fromhex('f0c545bdec3d79cdb186b72a5adc930d')
        bip39_mnemonic = "valid clay hunt such stuff traffic ship street clean street cave brave"
        assert cbl.Mnemonic.encode(entropy=entropy, words=12) == bip39_mnemonic

    def test_mnemonic_encode_two(self):
        # 24 Words use 32-Bytes, 256-Bit entropy
        entropy = bytes.fromhex(
            'b8899e2279449e3dfad2cdb260596bdd9850c8365846f67b072ec591e14f35fd')
        bip39_mnemonic = "review erupt mass verb enemy bus twice fluid raven actress foot robot lunar goat sunny angle wait subway slight menu bulk pole subject sauce"
        assert cbl.Mnemonic.encode(entropy=entropy, words=24) == bip39_mnemonic

    # **************************************************
    # Generate Decode
    # **************************************************
    def test_mnemonic_decode_one(self):
        # 12 Words use 16-Bytes, 128-Bit entropy
        entropy = bytes.fromhex('f0c545bdec3d79cdb186b72a5adc930d')
        bip39_mnemonic = "valid clay hunt such stuff traffic ship street clean street cave brave"
        assert cbl.Mnemonic.decode(bip39_mnemonic=bip39_mnemonic) == entropy

    def test_mnemonic_decode_two(self):
        # 12 Words use 16-Bytes, 128-Bit entropy - checksum ERROR
        # last word changed to cave from brave
        entropy = bytes.fromhex('f0c545bdec3d79cdb186b72a5adc930d')
        bip39_mnemonic = "valid clay hunt such stuff traffic ship street clean street cave cave"
        with pytest.raises(ValueError, match="Checksum error"):
            assert cbl.Mnemonic.decode(
                bip39_mnemonic=bip39_mnemonic) == "This should raise ValueError"

    def test_mnemonic_decode_three(self):
        # 12 Words use 16-Bytes, 128-Bit entropy - checksum ERROR
        # 8th word changed to act from traffic
        entropy = bytes.fromhex('f0c545bdec3d79cdb186b72a5adc930d')
        bip39_mnemonic = "valid clay hunt such stuff act ship street clean street cave brave"
        with pytest.raises(ValueError, match="Checksum error"):
            assert cbl.Mnemonic.decode(
                bip39_mnemonic=bip39_mnemonic) == "This should raise ValueError"

    def test_mnemonic_decode_four(self):
        # 24 Words use 32-Bytes, 256-Bit entropy
        entropy = bytes.fromhex(
            'b8899e2279449e3dfad2cdb260596bdd9850c8365846f67b072ec591e14f35fd')
        bip39_mnemonic = "review erupt mass verb enemy bus twice fluid raven actress foot robot lunar goat sunny angle wait subway slight menu bulk pole subject sauce"
        assert cbl.Mnemonic.decode(bip39_mnemonic=bip39_mnemonic) == entropy

    def test_mnemonic_decode_five(self):
        # 24 Words use 32-Bytes, 256-Bit entropy - checksum ERROR
        # 3rd word change from mass to act
        entropy = bytes.fromhex(
            'b8899e2279449e3dfad2cdb260596bdd9850c8365846f67b072ec591e14f35fd')
        bip39_mnemonic = "review erupt act verb enemy bus twice fluid raven actress foot robot lunar goat sunny angle wait subway slight menu bulk pole subject sauce"
        with pytest.raises(ValueError, match="Checksum error"):
            assert cbl.Mnemonic.decode(
                bip39_mnemonic=bip39_mnemonic) == "This should raise ValueError"
