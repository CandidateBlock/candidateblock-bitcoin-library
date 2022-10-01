import json

import candidateblock_bitcoin_library as cbl

if __name__ == "__main__":
    keys = cbl.Keys()
    print("*" * 120)
    wif_compressed = "Kxi7cFG5vvQ5KknQ2Szs5m4yxvra61TwzeKNWPnrNeCHy4SM5pHD"
    print(f"Private Key WIF (B58Check):\t\t\t\t{wif_compressed}")

    data = keys.decode_private_key_wif_compressed(private_key_wif_b58check=wif_compressed)
    print(f"Data:{json.dumps(data, indent=4)}")
    wif_hex = keys.get_private_key_hex()
    print(f"Private Key WIF (Hex):\t\t\t\t\t{wif_hex}")
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
