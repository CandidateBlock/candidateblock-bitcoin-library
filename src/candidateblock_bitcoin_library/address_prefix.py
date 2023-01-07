# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php


"""Base58 encoding.

Base58 and Base58Check encoding and decodings that are compatible
with the bitcoin network.
"""

# https://en.bitcoin.it/wiki/List_of_address_prefixes


class AddressPrefix(object):
    """String values of Hex byte

    Args:
        Enum (_type_): String values of Hex byte
    """
    PUBKEY_HASH_ADDRESS = "00"                        # Base58 = 1
    PAY_TO_SCRIPT_HASH_ADDRESS = "05"                 # Base58 = 3
    PRIVATE_KEY_WIF = "80"                            # Base58 = 5, K or L
    BIP_32_EXTENDED_PUBLIC_KEY = "0488b21e"           # Base58 = xpub
    BIP_32_EXTENDED_PRIVATE_KEY = "0488ade4"          # Base58 = xprv

    TESTNET_PUBKEY_HASH_ADDRESS = "6f"                # Base58 = m or n
    TESTNET_PAY_TO_SCRIPT_HASH_ADDRESS = "c4"         # Base58 = 2
    TESTNET_PRIVATE_KEY_WIF = "ef"                    # Base58 = 9 or c
    TESTNET_BIP_32_EXTENDED_PUBLIC_KEY = "043587cf"   # Base58 = tpub
    TESTNET_BIP_32_EXTENDED_PRIVATE_KEY = "04358394"  # Base58 = tprv
