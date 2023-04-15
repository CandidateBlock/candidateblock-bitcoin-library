# Copyright (c) 2023 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php


"""Prefix

Bitcoin uses encoded strings, which are in a Base58Check
encoding with the exception of Bech32 encodings. The encoding includes a
prefix (traditionally a single version byte), which affects the leading
symbol(s) in the encoded result.
"""

# https://en.bitcoin.it/wiki/List_of_address_prefixes


class Prefix(object):
    """bytes values of the address prefixes

    Args:
        Enum (_type_): bytes values of prefix
    """
    PAY_TO_PUBKEY_HASH = b'\x00'                             # Base58 = 1 (P2PKH)
    PAY_TO_SCRIPT_HASH = b'\x05'                             # Base58 = 3 (P2SH)
    PRIVATE_KEY_WIF = b'\x80'                                # Base58 = 5, K or L
    BIP_32_EXTENDED_PUBLIC_KEY = bytes.fromhex('0488B21E')   # Base58 = xpub
    BIP_32_EXTENDED_PRIVATE_KEY = bytes.fromhex('0488ADE4')  # Base58 = xprv

    TESTNET_PAY_TO_PUBKEY_HASH = b'\x6F'                             # Base58 = m or n (P2PKH)
    TESTNET_PAY_TO_SCRIPT_HASH = b'\xC4'                             # Base58 = 2 (P2SH)
    TESTNET_PRIVATE_KEY_WIF = b'\xEF'                                # Base58 = 9 or c
    TESTNET_BIP_32_EXTENDED_PUBLIC_KEY = bytes.fromhex('043587CF')   # Base58 = tpub
    TESTNET_BIP_32_EXTENDED_PRIVATE_KEY = bytes.fromhex('04358394')  # Base58 = tprv
