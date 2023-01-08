import candidateblock_bitcoin_library as cbl


if __name__ == "__main__":
    print("*" * 120 + "\n* Base Test\n" + "*" * 120)
    assert cbl.Base58.encode(input=bytes.fromhex("00000000000000000000")) == "1111111111"
    assert cbl.Base58.decode(s_base58="BukQL") == "0" + hex(123456789)[2:]