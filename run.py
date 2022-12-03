import json

import candidateblock_bitcoin_library as cbl

if __name__ == "__main__":
    print("*" * 120 + "\n* Wallet\n" + "*" * 120)
    wallet = cbl.Wallet()
    wallet.generate_mnemonic(words=24)

    # -------------------------------------------------------------------------------------------------
    # print("*" * 120 + "\n* Inputs\n" + "*" * 120)
    # keys = cbl.Keys()
    # # wif_compressed = "Kz3xE11U8AE5E4y7b6TtcgfVoybvrKhN6YmbsXepUzeiymFByEKk"
    # priv_key_hex = "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"
    # priv_key_wif = "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"
    # priv_key_wif_compressed = "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ"
    # print(f"Private Key (Hex):\t\t\t{priv_key_hex}")
    # print(f"Private Key WIF (B58Check):\t\t{priv_key_wif}")
    # print(f"Private Key WIF-Compressed (B58Check):\t{priv_key_wif_compressed}")

    # print("*" * 120 + "\n* Outputs - Base58 Check Decoded - Private Key WIF\n" + "*" * 120)
    # data = cbl.base58.b58check_decode(s_base58=priv_key_wif)
    # print(json.dumps(data, indent=2))

    # print("*" * 120 + "\n* Outputs - Base58 Check Decoded - Private Key WIF Compressed\n" + "*" * 120)
    # data = cbl.base58.b58check_decode(s_base58=priv_key_wif_compressed)
    # print(json.dumps(data, indent=2))

    # pub_key_b58check = "1thMirt546nngXqyPEz532S8fLwbozud8"
    # print("*" * 120 + "\n* Outputs - Base58 Check Decoded - Public Key Bitcoin Address\n" + "*" * 120)
    # data = cbl.base58.b58check_decode(s_base58=pub_key_b58check)
    # print(json.dumps(data, indent=2))

    # -------------------------------------------------------------------------------------------------
    # print("*" * 120 + "\n* Outputs - Private Key\n" + "*" * 120)
    # data = keys.decode_private_key_wif_compressed(
    #     private_key_wif_b58check=pk_wif_compressed)
    # print(json.dumps(data, indent=2))
    # print(f"Private Key (Dec):\t\t\t\t\t{keys.get_private_key()}")
    # print(f"Private Key (Hex):\t\t\t\t\t{keys.get_private_key_hex()}")
    # print(f"Private Key (B58):\t\t\t\t\t{keys.get_private_key_base58()}")
    # print(f"Private Key WIF (B58Check):\t\t\t\t{keys.get_private_key_wif()}")
    # print(
    #     f"Private Key WIF Compressed (B58Check):\t\t\t{keys.get_private_key_wif_compressed()}")
    # print("*" * 120 + "\n* Outputs - Public Key\n" + "*" * 120)
    # keys.generate_public_key()
    # print(f"Public Key (x,y):\t\t\t\t\t{keys.get_public_key()}")
    # print(f"Public Key (Hex):\t\t\t\t\t{keys.get_public_key_hex()}")
    # print(
    #     f"Public Key Bitcoin Address (B58Check):\t\t\t{keys.get_public_key_bitcoin_address()}")
    # print(
    #     f"Public Key Compressed (Hex):\t\t\t\t{keys.get_public_key_compressed_hex()}")
    # print(
    #     f"Public Key Compressed Bitcoin Address (B58Check):\t{keys.get_public_compressed_key_bitcoin_address()}")
