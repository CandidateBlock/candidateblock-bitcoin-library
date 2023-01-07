# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import candidateblock_bitcoin_library as cbl


class TestVersionPrefix:
    # **************************************************
    # Check enum values
    # **************************************************
    def test_version_prefix_one(self):
        assert cbl.AddressPrefix.PUBKEY_HASH_ADDRESS == "00"
        assert cbl.AddressPrefix.PAY_TO_SCRIPT_HASH_ADDRESS == "05"
        assert cbl.AddressPrefix.PRIVATE_KEY_WIF == "80"
        assert cbl.AddressPrefix.BIP_32_EXTENDED_PUBLIC_KEY == "0488b21e"
        assert cbl.AddressPrefix.BIP_32_EXTENDED_PRIVATE_KEY == "0488ade4"

        assert cbl.AddressPrefix.TESTNET_PUBKEY_HASH_ADDRESS == "6f"                # Base58 = m or n
        assert cbl.AddressPrefix.TESTNET_PAY_TO_SCRIPT_HASH_ADDRESS == "c4"
        assert cbl.AddressPrefix.TESTNET_PRIVATE_KEY_WIF == "ef"
        assert cbl.AddressPrefix.TESTNET_BIP_32_EXTENDED_PUBLIC_KEY == "043587cf"
        assert cbl.AddressPrefix.TESTNET_BIP_32_EXTENDED_PRIVATE_KEY == "04358394"
