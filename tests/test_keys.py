# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import pytest

import candidateblock_bitcoin_library as cbl

priv_key = bytes.fromhex(
    '0ae377964b26eba86f992a59f1600f256b9afc6fc6de6980f0140b69aba51dd6')


class TestKeys:
    # **************************************************
    # Public Key - Generation
    # **************************************************
    def test_keys_pub_key_gen_one(self):
        # Check random number is 32-bytes (256-bits) long
        assert len(cbl.Keys._random_secret()) == 32

    def test_keys_pub_key_gen_two(self):
        # Check range bounds of valid private key
        # Out of range
        assert cbl.Keys.is_priv_key_valid(b'\x00') is False
        assert cbl.Keys.is_priv_key_valid(
            priv_key=cbl.Keys._n.to_bytes(32, 'big')) is False
        # In range
        assert cbl.Keys.is_priv_key_valid(b'\x01') is True
        assert cbl.Keys.is_priv_key_valid(
            priv_key=(cbl.Keys._n - 1).to_bytes(32, 'big')) is True

    def test_keys_pub_key_gen_three(self):
        # Check random number is 32-bytes (256-bits) long
        assert len(cbl.Keys.generate_priv_key()) == 32
        # Check in range
        assert cbl.Keys.generate_priv_key() != b'\x00'
        assert cbl.Keys.generate_priv_key() < cbl.Keys._n.to_bytes(32, 'big')

    # **************************************************
    # Public Key - Encode tests
    # **************************************************
    def test_keys_pub_key_encode_one(self):
        # Check WIF Encode - MainNet, Compressed
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_key, is_compressed=True, is_mainnet=True)
        assert wif == 'KwasomKZ3F5btFki7Mb8ersoLVkfaKZqiP9X9mEqpi1wx79dAZXx'

    def test_keys_pub_key_encode_two(self):
        # Check WIF Encode - MainNet, not Compressed
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_key, is_compressed=False, is_mainnet=True)
        assert wif == '5Hu5iQdq3KbaH9KxzB6vPdDsNdsg6jisusnRxTLT1qiT3bQrWFy'

    def test_keys_pub_key_encode_three(self):
        # Check WIF Encode - Testnet, Compressed
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_key, is_compressed=True, is_mainnet=False)
        assert wif == 'cMwsGgKQUJms3hDyVmQG2BNrxj45EmfXnRHzGBhMKpfxCrHCHv2F'

    def test_keys_pub_key_encode_four(self):
        # Check WIF Encode - Testnet, not Compressed
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_key, is_compressed=False, is_mainnet=False)
        assert wif == '91fiJ9TNdYfiFCqFcWzqGDmq2JEPFuG5FpeP35gxMaTVpdvZLui'

    # **************************************************
    # Public Key - Decode tests
    # **************************************************
    def test_keys_pub_key_decode_one(self):
        # Check WIF Decode - MainNet, Compressed
        decoded_priv_key, is_compressed, is_mainnet = cbl.Keys.priv_key_wif_decode(
            wif_b58='KwasomKZ3F5btFki7Mb8ersoLVkfaKZqiP9X9mEqpi1wx79dAZXx')
        assert is_compressed is True
        assert is_mainnet is True
        assert decoded_priv_key == priv_key

    def test_keys_pub_key_decode_two(self):
        # Check WIF Decode - MainNet, not Compressed
        decoded_priv_key, is_compressed, is_mainnet = cbl.Keys.priv_key_wif_decode(
            wif_b58='5Hu5iQdq3KbaH9KxzB6vPdDsNdsg6jisusnRxTLT1qiT3bQrWFy')
        assert is_compressed is False
        assert is_mainnet is True
        assert decoded_priv_key == priv_key

    def test_keys_pub_key_decode_three(self):
        # Check WIF Decode - Testnet, Compressed
        decoded_priv_key, is_compressed, is_mainnet = cbl.Keys.priv_key_wif_decode(
            wif_b58='cMwsGgKQUJms3hDyVmQG2BNrxj45EmfXnRHzGBhMKpfxCrHCHv2F')
        assert is_compressed is True
        assert is_mainnet is False
        assert decoded_priv_key == priv_key

    def test_keys_pub_key_decode_four(self):
        # Check WIF Decode - Testnet, not Compressed
        decoded_priv_key, is_compressed, is_mainnet = cbl.Keys.priv_key_wif_decode(
            wif_b58='91fiJ9TNdYfiFCqFcWzqGDmq2JEPFuG5FpeP35gxMaTVpdvZLui')
        assert is_compressed is False
        assert is_mainnet is False
        assert decoded_priv_key == priv_key

    # **************************************************
    # Private Key - Generation
    # **************************************************
    def test_keys_priv_key_generation_one(self):
        priv_key = bytes.fromhex(
            '3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6')

        # WIF uncompressed
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_key, is_compressed=False, is_mainnet=True)
        assert wif == "5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K"

        # WIF compressed
        wif = cbl.Keys.priv_key_wif_encode(
            priv_key=priv_key, is_compressed=True, is_mainnet=True)
        assert wif == "KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S"

        # Public Key Uncompressed
        pub_key = cbl.Keys.generate_pub_key(priv_key=priv_key, is_compressed=False)
        result = bytes.fromhex(
            '045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176')
        assert pub_key == result

        # Public Key Uncompressed as Bitcion Address (Base58Check)
        pub_key_hash160 = cbl.BtcHash.hash160(value=pub_key)
        btc_address = cbl.Base58.check_encode(
            payload=cbl.Prefix.PAY_TO_PUBKEY_HASH + pub_key_hash160)
        result = "1thMirt546nngXqyPEz532S8fLwbozud8"

        assert btc_address == result

        # Public Key Compressed
        pub_key = cbl.Keys.generate_pub_key(priv_key=priv_key, is_compressed=True)
        result = bytes.fromhex(
            '025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec')
        assert pub_key == result

        # Public Key Compressed as Bitcion Address (Base58Check)
        pub_key_hash160 = cbl.BtcHash.hash160(value=pub_key)
        btc_address = cbl.Base58.check_encode(
            payload=cbl.Prefix.PAY_TO_PUBKEY_HASH + pub_key_hash160)
        result = "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3"
        assert btc_address == result
