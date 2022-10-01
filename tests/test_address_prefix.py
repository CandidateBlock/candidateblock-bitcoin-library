# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
# import candidateblock_bitcoin_library as cbl
import candidateblock_bitcoin_library as cbl


class TestVersionPrefix:
    # **************************************************
    # Check enum values
    # **************************************************
    def test_version_prefix_one(self):
        assert cbl.AddressPrefix.PUBKEY_HASH_ADDRESS.value == "00"
        assert cbl.AddressPrefix.PAY_TO_SCRIPT_HASH_ADDRESS.value == "05"
        assert cbl.AddressPrefix.PRIVATE_KEY_WIF.value == "80"
        assert cbl.AddressPrefix.BIP_32_EXTENDED_PUBLIC_KEY.value == "0488b21e"
        assert cbl.AddressPrefix.BIP_32_EXTENDED_PRIVATE_KEY.value == "048ade4"

        assert cbl.AddressPrefix.TESTNET_PUBKEY_HASH_ADDRESS.value == "6f"                # Base58 = m or n
        assert cbl.AddressPrefix.TESTNET_PAY_TO_SCRIPT_HASH_ADDRESS.value == "c4"
        assert cbl.AddressPrefix.TESTNET_PRIVATE_KEY_WIF.value == "ef"
        assert cbl.AddressPrefix.TESTNET_BIP_32_EXTENDED_PUBLIC_KEY.value == "043587cf"
        assert cbl.AddressPrefix.TESTNET_BIP_32_EXTENDED_PRIVATE_KEY.value == "04358394"
