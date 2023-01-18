# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import candidateblock_bitcoin_library as cbl


class TestVersionPrefix:
    # **************************************************
    # Check enum values
    # **************************************************
    def test_version_prefix_one(self):
        assert cbl.Prefix.PAY_TO_PUBKEY_HASH == b'\x00'
        assert cbl.Prefix.PAY_TO_SCRIPT_HASH == b'\x05'
        assert cbl.Prefix.PRIVATE_KEY_WIF == b'\x80'
        assert cbl.Prefix.BIP_32_EXTENDED_PUBLIC_KEY == bytes.fromhex("0488b21e")
        assert cbl.Prefix.BIP_32_EXTENDED_PRIVATE_KEY == bytes.fromhex("0488ade4")

        assert cbl.Prefix.TESTNET_PAY_TO_PUBKEY_HASH == b'\x6f'                # Base58 = m or n
        assert cbl.Prefix.TESTNET_PAY_TO_SCRIPT_HASH == b'\xc4'
        assert cbl.Prefix.TESTNET_PRIVATE_KEY_WIF == b'\xef'
        assert cbl.Prefix.TESTNET_BIP_32_EXTENDED_PUBLIC_KEY == bytes.fromhex(
            "043587cf")
        assert cbl.Prefix.TESTNET_BIP_32_EXTENDED_PRIVATE_KEY == bytes.fromhex(
            "04358394")
