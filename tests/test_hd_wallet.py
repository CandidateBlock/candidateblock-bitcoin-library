# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import pytest

import candidateblock_bitcoin_library as cbl

from bip39_test_vectors import bip39_test_vectors


class TestHdWallet:
    # **************************************************
    # master_key_generation
    # **************************************************
    def test_bip32_master_key_generation_one(self):
        # Master Key = Public Key, on Mainnet, depth=0, child=0
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        master_priv_key, master_chain_code = cbl.HdWallet.master_key_generation(
            seed=seed)
        extended_key = cbl.HdWallet.encode(
            key=master_priv_key, chain_code=master_chain_code, parent_key=b'', depth=0, child=0, is_master=True, is_private=True, is_mainnet=True)
        assert extended_key == "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"

    def test_bip32_master_key_generation_two(self):
        # Master Key = Public Key, on Testnet, depth=0, child=0
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        master_priv_key, master_chain_code = cbl.HdWallet.master_key_generation(
            seed=seed)
        extended_key = cbl.HdWallet.encode(
            key=master_priv_key, chain_code=master_chain_code, parent_key=b'', depth=0, child=0, is_master=True, is_private=True, is_mainnet=False)
        assert extended_key == "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"

    # **************************************************
    # Full Test Suit
    # https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    # **************************************************
    def test_full_test_suit_one(self):
        for test_data in bip39_test_vectors:
            # entropy = bytes.fromhex(test_data[0])
            # bip39_mnemonic = test_data[1]
            # words = len(bip39_mnemonic.split())
            # passphrase = 'TREZOR'
            bip39_seed = bytes.fromhex(test_data[2])
            extended_key = test_data[3]
            master_priv_key, master_chain_code = cbl.HdWallet.master_key_generation(
                seed=bip39_seed)
            ext_key = cbl.HdWallet.encode(
                key=master_priv_key, chain_code=master_chain_code, parent_key=b'', depth=0, child=0, is_master=True, is_private=True, is_mainnet=True)
            assert ext_key == extended_key
