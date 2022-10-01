# import candidateblock_bitcoin_library as cbl

import candidateblock_bitcoin_library as cbl

if __name__ == "__main__":
    keys = cbl.Keys()
    print("*" * 120)
    wif_compressed = "Kz3xE11U8AE5E4y7b6TtcgfVoybvrKhN6YmbsXepUzeiymFByEKk"
    print(f"Private Key WIF (B58Check):\t\t\t\t{wif_compressed}")
    wif_hex = cbl.base58.b58decode(s_base58=wif_compressed)
    print(f"Private Key WIF (Hex):\t\t\t\t\t{wif_hex}")
    prefix = wif_hex[:2]
    wif_hex = wif_hex[2:]
    pk = wif_hex[:64]
    wif_hex = wif_hex[64:]
    compressed = wif_hex[:2]
    wif_hex = wif_hex[2:]
    checksum = wif_hex

    # pk = "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6"
    keys.private_key = int(pk, 16)
    print(f"Private Key (Dec):\t\t\t\t\t{keys.get_private_key()}")
    print(f"Private Key (Hex):\t\t\t\t\t{keys.get_private_key_hex()}")
    print(f"Private Key (B58):\t\t\t\t\t{keys.get_private_key_base58()}")
    print(f"Private Key WIF (B58Check):\t\t\t\t{keys.get_private_key_wif()}")
    print(
        f"Private Key WIF Compressed (B58Check):\t\t\t{keys.get_private_key_wif_compressed()}")
    keys.generate_public_key()
    print("-" * 120)
    print(f"Public Key (x,y):\t\t\t\t\t{keys.get_public_key()}")
    print(f"Public Key (Hex):\t\t\t\t\t{keys.get_public_key_hex()}")
    print(
        f"Public Key Bitcoin Address (B58Check):\t\t\t{keys.get_public_key_bitcoin_address()}")
    print(
        f"Public Key Compressed (Hex):\t\t\t\t{keys.get_public_key_compressed_hex()}")
    print(
        f"Public Key Compressed Bitcoin Address (B58Check):\t{keys.get_public_compressed_key_bitcoin_address()}")
    print("*" * 120)
