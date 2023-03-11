# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import csv

# import pytest
from bip39_test_vectors import bip39_test_vectors

import candidateblock_bitcoin_library as cbl

# seed, chain, ext_pub, ext_prv
seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
bip39_test_vector_one = (
    [seed,
     "m",
     "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
     "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"],
    [seed,
     "m/0'",
     "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
     "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"],
    [seed,
     "m/0'/1",
     "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
     "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"],
    [seed,
     "m/0'/1/2'",
     "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
     "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"],
    [seed,
     "m/0'/1/2'/2",
     "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
     "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"],
    [seed,
     "m/0'/1/2'/2/1000000000",
     "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
     "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"],
)


class TestHdWallet:
    # **************************************************
    # master_key_generation
    # **************************************************
    def test_master_key_generation_one(self):
        # Master Key = Public Key, on Mainnet, depth=0, child=0
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        values = cbl.HdWallet.master_key_generation(seed=seed)
        master_priv_key, master_chain_code, master_fingerprint = values
        extended_key = cbl.HdWallet.encode(
            key=master_priv_key, chain_code=master_chain_code, parent_key=b'', depth=0, child=0, is_master=True, is_private=True, is_mainnet=True)
        assert extended_key == "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"

    def test_master_key_generation_two(self):
        # Master Key = Public Key, on Testnet, depth=0, child=0
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        values = cbl.HdWallet.master_key_generation(seed=seed)
        master_priv_key, master_chain_code, master_fingerprint = values
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
            values = cbl.HdWallet.master_key_generation(seed=bip39_seed)
            master_priv_key, master_chain_code, master_fingerprint = values
            ext_key = cbl.HdWallet.encode(
                key=master_priv_key, chain_code=master_chain_code, parent_key=b'', depth=0, child=0, is_master=True, is_private=True, is_mainnet=True)
            assert ext_key == extended_key

    # **************************************************
    # child_key_derivation
    # **************************************************
    def test_child_key_derivation_one(self):
        # m/0' Master Key = Public Key, on Mainnet, depth=1, child=0' Hardended 0x80000000
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        values = cbl.HdWallet.master_key_generation(seed=seed)
        master_priv_key, master_chain_code, master_fingerprint = values
        depth = 1
        index = cbl.HdWallet.HARDEND + 0
        is_private = True
        is_master = False
        is_mainnet = True
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=master_priv_key, parent_chaincode=master_chain_code, index=index, is_private=is_private)
        child_ext_key_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                parent_key=master_priv_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_b58 == "xprv9ukW2Usuz4v7Yd2EC4vNXaMckdsEdgBA9n7MQbqMJbW9FuHDWWjDwzEM2h6XmFnrzX7JVmfcNWMEVoRauU6hQpbokqPPNTbdycW9fHSPYyF"

    def test_child_key_derivation_two(self):
        # m/0 Master Key = Public Key, on Mainnet, depth=1, child=0 NOT Hardended 0x00000000
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        values = cbl.HdWallet.master_key_generation(seed=seed)
        master_priv_key, master_chain_code, master_fingerprint = values
        depth = 1
        index = 0
        is_private = True
        is_master = False
        is_mainnet = True
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=master_priv_key, parent_chaincode=master_chain_code, index=index, is_private=is_private)
        child_ext_key_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                parent_key=master_priv_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_b58 == "xprv9ukW2UsmeQP9NB14w61cimzwEKbUJxHCypMb1PpEafjCETz69a6tp8aYdMkHfz6U49Ut262f9MpGZkCna1zDhEfW2BGkSehvrxd5ueR4TBe"

    def test_child_key_derivation_three(self):
        # m/0'/0' Master Key = Public Key, on Mainnet, depth=2, child=0' Hardended 0x80000000
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        values = cbl.HdWallet.master_key_generation(seed=seed)
        master_priv_key, master_chain_code, master_fingerprint = values
        parent_key = master_priv_key
        depth = 1
        index = cbl.HdWallet.HARDEND + 0
        is_private = True
        is_master = False
        is_mainnet = True
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=master_priv_key, parent_chaincode=master_chain_code, index=index, is_private=is_private)
        child_ext_key_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                parent_key=parent_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_b58 == "xprv9ukW2Usuz4v7Yd2EC4vNXaMckdsEdgBA9n7MQbqMJbW9FuHDWWjDwzEM2h6XmFnrzX7JVmfcNWMEVoRauU6hQpbokqPPNTbdycW9fHSPYyF"

        parent_key = child_ext_key
        depth = 2
        index = cbl.HdWallet.HARDEND + 0
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=child_ext_key, parent_chaincode=child_chain_code, index=index, is_private=is_private)
        child_ext_key_2_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                  parent_key=parent_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_2_b58 == "xprv9w83TkwTJSpYjV4hWcxttB9bQWHdrFCPzCLnMHKceyd4WGBfsUgijUirvMaHM6TFBqQegpt3hZysUeBP8PFmkjPWitahm71vjNhMLqKmuLb"

    def test_child_key_derivation_four(self):
        # BIP44
        # m/44'/1'/0'/0 Mainnet
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        seed = bytes.fromhex(
            '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        values = cbl.HdWallet.master_key_generation(seed=seed)
        master_priv_key, master_chain_code, master_fingerprint = values
        parent_key = master_priv_key
        depth = 1
        index = cbl.HdWallet.HARDEND + 44  # Purpose 44 (BIP44)
        is_private = True
        is_master = False
        is_mainnet = True
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=master_priv_key, parent_chaincode=master_chain_code, index=index, is_private=is_private)
        child_ext_key_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                parent_key=parent_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_b58 == "xprv9ukW2Usuz4v9T49296K5xDezLcFCEaGoLo3YGAJNuFmx1McKebuH2S5C5VhaFsBxuChmARtTHRLKnmLjRSL7vGuyDrCaBh7mfdyefDdp5hh"

        parent_key = child_ext_key
        depth = 2
        index = cbl.HdWallet.HARDEND + 1  # Coin = 1 => Bitcoin
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=child_ext_key, parent_chaincode=child_chain_code, index=index, is_private=is_private)
        child_ext_key_2_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                  parent_key=parent_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_2_b58 == "xprv9wnZLsHUEcR3XFfVUmxv2PBAJ1FhkM4K7rtx44b4Fc7dgHfSjzfsPhFeuGdWaLMieRr8xQP5r2i1qdVLRaVEXMmrJvq5PvGDBKSdLkGhWeW"

        parent_key = child_ext_key
        depth = 3
        index = cbl.HdWallet.HARDEND + 0  # Account = 0
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=child_ext_key, parent_chaincode=child_chain_code, index=index, is_private=is_private)
        child_ext_key_2_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                  parent_key=parent_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_2_b58 == "xprv9xiGX2q91Zr2DSdtDHeTJHfaTPvi4JdFw4x5HjSSJcPztu96LbN8juUH4QNfS9bKYLo3jcJv9JWbUcPwbebxPXzEbu7PA3zXaCucrZSYXEK"

        parent_key = child_ext_key
        depth = 4
        index = 0  # External(0)[Pay Address] / Internal(1)[Change Address] = 0
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=child_ext_key, parent_chaincode=child_chain_code, index=index, is_private=is_private)
        child_ext_key_2_b58 = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code,
                                                  parent_key=parent_key, depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        assert child_ext_key_2_b58 == "xprvA13CjycRW3qpVzBjpJKHDXAR4LuQ1Dur13Wv4cGzxQqNU8LTZ4hRSN6mJgPuHFg55LrZVzKwDbaizeXr4e6RuNwQoqSNVRLgAmsqybd6yNm"

        parent_key = child_ext_key
        depth = 5
        index = 0  # First Address
        child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
            parent_key=child_ext_key, parent_chaincode=child_chain_code, index=index, is_private=is_private)
        # Check Private Key WIF
        priv_key_wif = cbl.Keys.priv_key_wif_encode(
            priv_key=child_ext_key, is_compressed=True, is_mainnet=is_mainnet)
        assert priv_key_wif == "L4jNzRuAe1kHvGj7N5UXd3m9erYWRkV6EnXiHR6AoMM37dEzUkTV"
        # Check Public Key (Compressed)
        pub_key = cbl.Keys.generate_pub_key(
            priv_key=child_ext_key, is_compressed=True)
        assert pub_key.hex() == "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6"
        # Check Public Key (Compressed) as Bitcoin Address
        address = cbl.Keys.btc_address_p2pkh(pub_key=pub_key, is_mainnet=True)
        # address = cbl.Base58.check_encode(payload=cbl.Prefix.PAY_TO_PUBKEY_HASH + cbl.BtcHash.hash160(pub_key))
        assert address == "16JcQVoL61QsLCPS6ek8UJZ52eRfaFqLJt"

    # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_Vectors

    def test_bip32_test_vector_one(self):
        seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        # Chain m
        values = cbl.HdWallet.master_key_generation(seed=seed)
        master_priv_key, master_chain_code, master_fingerprint = values
        extended_key = cbl.HdWallet.encode(
            key=master_priv_key, chain_code=master_chain_code, parent_key=b'', depth=0, child=0, is_master=True, is_private=True, is_mainnet=True)
        assert extended_key == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

    def test_bip32_test_vector_two(self):
        for row in bip39_test_vector_one:
            seed = row[0]
            path = row[1]
            xpub = row[2]
            xprv = row[3]
            child_ext_key = b''
            child_chain_code = b''
            path_array = path.upper().split("/")
            for depth, level in enumerate(path_array):
                is_private = True
                is_mainnet = True
                # Update parent for next loop
                parent_key = child_ext_key
                parent_chaincode = child_chain_code
                if depth == 0 and level == "M":
                    # Master node
                    is_master = True
                    values = cbl.HdWallet.master_key_generation(seed=seed)
                    child_ext_key, child_chain_code, master_fingerprint = values
                    index = 0
                else:
                    # child node
                    is_master = False
                    hardend = level.split("\'")
                    if len(hardend) > 1:
                        HARDEND = 2**31
                        index = HARDEND + int(hardend[0])
                    else:
                        index = int(hardend[0])

                    child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
                        parent_key=parent_key, parent_chaincode=parent_chaincode, index=index, is_private=is_private)

            new_xprv = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code, parent_key=parent_key,
                                           depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
            assert xprv == new_xprv
            # Public to Private Key
            is_private = False
            new_public_key = cbl.Keys.generate_pub_key(
                priv_key=child_ext_key, is_compressed=True)
            new_xpub = cbl.HdWallet.encode(key=new_public_key, chain_code=child_chain_code, parent_key=parent_key,
                                           depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
            assert xpub == new_xpub

    def test_child_key_derivation_five(self):
        # BIP44 - read from csv test file
        # Entropy = 0x00000000000000000000000000000000
        # BIP-39 Mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

        with open('tests/bip32-test-vectors.csv', newline='') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in csv_reader:
                if row[0][: 1] == "#":
                    # Skip row as first char is a comment #
                    pass
                else:
                    seed = bytes.fromhex(row[0])
                    path = row[1]
                    address = row[2]
                    public_key = bytes.fromhex(row[3])
                    private_key_wif = row[4]
                    parent_key = b''
                    parent_chaincode = b''
                    path_array = path.upper().split("/")
                    for depth, level in enumerate(path_array):
                        if depth == 0 and level == "M":
                            # Master node
                            values = cbl.HdWallet.master_key_generation(seed=seed)
                            master_priv_key, master_chain_code, master_fingerprint = values
                            # Update parent for next loop
                            parent_key = master_priv_key
                            parent_chaincode = master_chain_code
                        else:
                            # child node
                            hardend = level.split("\'")
                            if len(hardend) > 1:
                                HARDEND = 2**31
                                index = HARDEND + int(hardend[0])
                            else:
                                index = int(hardend[0])

                            is_private = True
                            is_mainnet = True
                            child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
                                parent_key=parent_key, parent_chaincode=parent_chaincode, index=index, is_private=is_private)
                            # Update parent for next loop
                            parent_key = child_ext_key
                            parent_chaincode = child_chain_code

                        if depth == len(path_array) - 1:
                            # Check Private Key WIF
                            priv_key_wif = cbl.Keys.priv_key_wif_encode(
                                priv_key=child_ext_key, is_compressed=True, is_mainnet=is_mainnet)
                            assert priv_key_wif == private_key_wif
                            # Check Public Key (Compressed)
                            pub_key = cbl.Keys.generate_pub_key(
                                priv_key=child_ext_key, is_compressed=True)
                            assert pub_key == public_key
                            # Check Public Key (Compressed) as Bitcoin Address
                            btc_address = cbl.Keys.btc_address_p2pkh(pub_key=pub_key, is_mainnet=is_mainnet)
                            # address = cbl.Base58.check_encode(payload=cbl.Prefix.PAY_TO_PUBKEY_HASH + cbl.BtcHash.hash160(pub_key))
                            assert btc_address == address
