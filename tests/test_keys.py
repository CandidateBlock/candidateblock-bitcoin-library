# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import pytest

import candidateblock_bitcoin_library as cbl


class TestKeys:
    # **************************************************
    # encode tests
    # **************************************************
    def test_keys_one(self):
        # Check random number is 32-bytes (256-bits) long
        assert len(cbl.Keys._random_secret()) == 32

    def test_keys_two(self):
        # Check range bounds of valid private key
        # Out of range
        assert cbl.Keys.is_priv_key_valid(b'\x00') is False
        assert cbl.Keys.is_priv_key_valid(
            priv_key=cbl.Keys._n.to_bytes(32, 'big')) is False
        # In range
        assert cbl.Keys.is_priv_key_valid(b'\x01') is True
        assert cbl.Keys.is_priv_key_valid(
            priv_key=(cbl.Keys._n - 1).to_bytes(32, 'big')) is True

    def test_keys_three(self):
        # Check random number is 32-bytes (256-bits) long
        assert len(cbl.Keys.generate_priv_key()) == 32
        # Check in range
        assert cbl.Keys.generate_priv_key() != b'\x00'
        assert cbl.Keys.generate_priv_key() < cbl.Keys._n.to_bytes(32, 'big')

    def test_keys_four(self):
        # Check WIF Encode - MainNet, Compressed
        priv_hex = bytes.fromhex(
            '0ae377964b26eba86f992a59f1600f256b9afc6fc6de6980f0140b69aba51dd6')
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_hex, is_compressed=True, is_mainnet=True)
        assert wif == 'KwasomKZ3F5btFki7Mb8ersoLVkfaKZqiP9X9mEqpi1wx79dAZXx'

    def test_keys_five(self):
        # Check WIF Encode - MainNet, not Compressed
        priv_hex = bytes.fromhex(
            '0ae377964b26eba86f992a59f1600f256b9afc6fc6de6980f0140b69aba51dd6')
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_hex, is_compressed=False, is_mainnet=True)
        assert wif == '5Hu5iQdq3KbaH9KxzB6vPdDsNdsg6jisusnRxTLT1qiT3bQrWFy'

    def test_keys_six(self):
        # Check WIF Encode - Testnet, Compressed
        priv_hex = bytes.fromhex(
            '0ae377964b26eba86f992a59f1600f256b9afc6fc6de6980f0140b69aba51dd6')
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_hex, is_compressed=True, is_mainnet=False)
        assert wif == 'cMwsGgKQUJms3hDyVmQG2BNrxj45EmfXnRHzGBhMKpfxCrHCHv2F'

    def test_keys_seven(self):
        # Check WIF Encode - Testnet, not Compressed
        priv_hex = bytes.fromhex(
            '0ae377964b26eba86f992a59f1600f256b9afc6fc6de6980f0140b69aba51dd6')
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_hex, is_compressed=False, is_mainnet=False)
        assert wif == '91fiJ9TNdYfiFCqFcWzqGDmq2JEPFuG5FpeP35gxMaTVpdvZLui'

    # def test_keys_eight(self):
    #     # Check WIF Decode - MainNet, Compressed
    #     priv_key, is_compressed, is_mainnet = cbl.Keys.priv_key_wif_decode(
    #         wif_base58='91fiJ9TNdYfiFCqFcWzqGDmq2JEPFuG5FpeP35gxMaTVpdvZLui')
