# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php
import pytest

import candidateblock_bitcoin_library as cbl

# Base58 Test Vectors
b58_test_vectors = (
    [bytes.fromhex("61"), "2g"],
    [bytes.fromhex("626262"), "a3gV"],
    [bytes.fromhex("636363"), "aPEr"],
    [bytes.fromhex("73696d706c792061206c6f6e6720737472696e67"),
        "2cFupjhnEsSn59qHXstmK2ffpLv2"],
    [bytes.fromhex("516b6fcd0f"), "ABnLTmg"],
    [bytes.fromhex("bf4f89001e670274dd"), "3SEo3LWLoPntC"],
    [bytes.fromhex("572e4794"), "3EFU7m"],
    [bytes.fromhex("ecac89cad93923c02321"), "EJDM8drfXA6uyA"],
    [bytes.fromhex("10c8511e"), "Rt5zm"],
    [bytes.fromhex('000123456789abcdef'), "1C3CPq7c8PY"],
    [bytes.fromhex("00000000000000000000"), "1111111111"],
    [bytes.fromhex("00eb15231dfceb60925886b67d065299925915aeb172c06647"),
        "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"],
    [bytes.fromhex("000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5"),
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"],
    [bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY"]
)

PUBKEY_HASH = b'\x00'
COMPRESSED = b'\x01'
MAINNET = b'\x80'
TESTNET = b'\xEF'

# Base58 CHECK Test Vectors
b58check_test_vectors = (
    # Bitcoin Address
    [PUBKEY_HASH + bytes.fromhex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"),
     "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"],
    # Private key in WIF base58 check output format (Mainnet '\x80'), not compressed
    [MAINNET + bytes.fromhex("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"),
     "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"],
    # Private key in WIF-compressed base58 check output format (Mainnet '\x80'), extra '\x01' at end of input
    [MAINNET + bytes.fromhex("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd") + COMPRESSED,
     "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ"],
    # Mainnet Private key in WIF not compressed base58 check output format (Mainnet '\x80')
    [MAINNET + bytes.fromhex("ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2"),
     "5Kdc3UAwGmHHuj6fQD1LDmKR6J3SwYyFWyHgxKAZ2cKRzVCRETY"],
    # Mainnet Private key in WIF compressed base58 check output format (Mainnet '\x80'), extra 01 at end of input
    [MAINNET + bytes.fromhex("ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2") + COMPRESSED,
     "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6"],
    # Testnet Private key in WIF not compressed base58 check output format (Testnet '\xef')
    [TESTNET + bytes.fromhex("ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2"),
     "93QEdCzUrzMRsnbx2YuF6MsNjxQA6iWSrv9e2wX4NM4UmYzUsLn"],
    # Testnet Private key in WIF compressed base58 check output format (Testnet '\xef'), extra 01 at end of input
    [TESTNET + bytes.fromhex("ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2") + COMPRESSED,
     "cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm"],
)


class TestBase58:
    # **************************************************
    # encode tests
    # **************************************************
    def test_encode_one(self):
        # Empty input
        with pytest.raises(ValueError, match="Input bytes can not be empty"):
            assert cbl.Base58.encode(input=b'') == "This should raise ValueError"

    def test_encode_two(self):
        # Odd number of hexadecimal digits for the byte in string
        with pytest.raises(ValueError, match=r"non-hexadecimal number found in fromhex\(\) arg at position"):
            assert cbl.Base58.encode(input=bytes.fromhex(
                '123456789')) == "This should raise ValueError"

    def test_encode_three(self):
        for test_data in b58_test_vectors:
            assert cbl.Base58.encode(input=test_data[0]) == test_data[1]

    # **************************************************
    # decode tests
    # **************************************************
    def test_decode_one(self):
        assert cbl.Base58.decode(base58="BukQL").hex() == "0" + hex(123456789)[2:]

    def test_decode_two(self):
        assert cbl.Base58.decode(base58="1C3CPq7c8PY").hex() == "000123456789abcdef"

    def test_decode_three(self):
        for test_data in b58_test_vectors:
            assert cbl.Base58.decode(base58=test_data[1]) == test_data[0]

    def test_decode_four(self):
        # Invalid base58 and null char at end / start
        with pytest.raises(ValueError, match="string argument should contain only Base58 characters"):
            assert cbl.Base58.decode(base58="invalid") != "Not Valid Base58 Char"
        with pytest.raises(ValueError, match="string argument should contain only Base58 characters"):
            assert cbl.Base58.decode(base58="invalid\0") != "Not Valid Base58 Char"
        with pytest.raises(ValueError, match="string argument should contain only Base58 characters"):
            assert cbl.Base58.decode(base58="\0invalid") != "Not Valid Base58 Char"

    def test_decode_five(self):
        # Valid & Invalid base58 and null char
        assert cbl.Base58.decode(base58="good").hex() == "768320"
        with pytest.raises(ValueError, match="string argument should contain only Base58 characters"):
            assert cbl.Base58.decode(base58="bad0IOl") == "Not Valid Base58 Char"
        with pytest.raises(ValueError, match="string argument should contain only Base58 characters"):
            assert cbl.Base58.decode(
                base58="goodbad0IOl") != "Not Valid Base58 Char"
        with pytest.raises(ValueError, match="string argument should contain only Base58 characters"):
            assert cbl.Base58.decode(
                base58="good\0bad0IOl") != "Not Valid Base58 Char"

    def test_decode_six(self):
        # check that decode skips whitespace, but still fails with unexpected non-whitespace at the end.
        assert cbl.Base58.decode(
            base58=" \t\n\v\f\r skip \r\f\v\n\t ").hex() == "971a55"
        with pytest.raises(ValueError, match="string argument should contain only Base58 characters"):
            assert cbl.Base58.decode(
                base58=" \t\n\v\f\r skip \r\f\v\n\t a").hex() == "971a55"

    # **************************************************
    # encode_check tests
    # **************************************************
    def test_enccode_check_one(self):
        # Empty input
        with pytest.raises(ValueError, match=r"Input payload \(bytes\) can not be empty"):
            assert cbl.Base58.check_encode(payload=b'') == "This should raise ValueError"

    def test_enccode_check_two(self):
        for test_data in b58check_test_vectors:
            assert cbl.Base58.check_encode(payload=test_data[0]) == test_data[1]
