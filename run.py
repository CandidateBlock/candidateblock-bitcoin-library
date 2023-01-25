# import binascii
import hashlib
import hmac

import candidateblock_bitcoin_library as cbl


if __name__ == "__main__":
    print("*" * 120 + "\n* Wallet\n" + "*" * 120)
    wallet = cbl.HdWallet()
    # # valid values 12, 15, 18, 21 or 24
    # wallet.bip39_generate_mnemonic(words=24)
    # print(wallet.bip39_mnemonic)
    # print("-" * 120)
    # wallet.bip39_mnemonic_decode(bip39_mnemonic=wallet.bip39_mnemonic)

    print("-" * 120 + "\n* Mnemonic Sentence\n" + "-" * 120)
    mnemonic_sentence = wallet.bip39_mnemonic_encode(entropy_int=int(
        'c1e24e5917779d297e14d45f14e1a1a', 16), words=12)
    print(mnemonic_sentence)

    print("-" * 120 + "\n* Mnemonic To 512-Bit Root Seed\n" + "-" * 120)
    seed_bytes = wallet.bip39_mnemonic_to_root_seed(
        mnemonic_sentence=mnemonic_sentence, passphrase='')
    print(f'512-Bit Root Seed: {seed_bytes.hex()}')

    print("-" * 120)
    # seed_bytes = int('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be', 16).to_bytes(
    #     length=64, byteorder='big', signed=False)
    seed_hmac_sha512 = hmac.new(key=b"Bitcoin seed", msg=seed_bytes,
                                digestmod=hashlib.sha512).digest()
    master_private_key_256 = seed_hmac_sha512[:32]  # Left 256-bits
    master_chain_code_256 = seed_hmac_sha512[32:]   # Right 256-bits
    print(f'seed_hmac_sha512: {seed_hmac_sha512} bytes: {len(seed_hmac_sha512)}')
    print(f'seed_hmac_sha512 0x: {seed_hmac_sha512.hex()}')
    print(f'master_private_key_256 0x: {master_private_key_256.hex()}')
    print(f'master_chain_code_256 0x: {master_chain_code_256.hex()}')

    print("-" * 120 + "\n* Mnemonic To 512-Bit Root Seed\n" + "-" * 120)
    wallet.master_key_generation(seed=seed_bytes)

    keys = cbl.Keys()
    keys.private_key = int.from_bytes(
        bytes=master_private_key_256, byteorder='big', signed=False)
    keys.generate_public_key()
    master_public_key_256 = keys.get_public_key_compressed_hex()

    # xprv = b"\x00" * 9  # Depth 1-byte, parent fingerprint 4-bytes, and child number 4-bytes
    # Depth 1-byte
    xprv = int(0).to_bytes(length=1, byteorder='big', signed=False)
    # parent fingerprint 4-bytes
    xprv += int(0).to_bytes(length=4, byteorder='big', signed=False)
    # child number 4-bytes
    xprv += int(0).to_bytes(length=4, byteorder='big', signed=False)
    xprv += master_chain_code_256
    xprv += b"\x00" + master_private_key_256
    xprv_hex = xprv.hex()
    xprv_base58 = cbl.Base58.check_encode(
        s_hex=xprv_hex, version_prefix=cbl.Prefix.BIP_32_EXTENDED_PRIVATE_KEY)
    print(f'xprv_base58: {xprv_base58}')

    # M/0'
    print("-" * 120 + "\n* m/0'\n" + "-" * 120)
    wallet.child_key_derivation(parent_key=master_private_key_256,
                                      parent_chaincode=master_chain_code_256,
                                      depth=1,
                                      index=0 + 2**31,
                                      is_private=True)

    # M/0'
    print("-" * 120 + "\n* m/0'\n" + "-" * 120)
    parent_priv_key = master_private_key_256
    parent_chain_code = master_chain_code_256
    index_num = 0
    hardened_index = 2**31
    hardened_index_num = (index_num + hardened_index).to_bytes(length=4,
                                                               byteorder='big', signed=False)
    hash_input = b"\x00" + parent_priv_key + hardened_index_num
    hmac_sha512 = hmac.new(key=parent_chain_code,
                           msg=hash_input,
                           digestmod=hashlib.sha512).digest()
    child_priv_key_256 = hmac_sha512[:32]  # Left 256-bits
    parent_priv_key_int = int.from_bytes(
        bytes=parent_priv_key, byteorder='big', signed=False)
    child_priv_key_int = int.from_bytes(
        bytes=child_priv_key_256, byteorder='big', signed=False)
    # _p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    new_child_priv_key_int = int((child_priv_key_int + parent_priv_key_int) % n)
    new_child_priv_key_256 = new_child_priv_key_int.to_bytes(
        length=32, byteorder='big', signed=False)

    child_chain_code_256 = hmac_sha512[32:]   # Right 256-bits

    depth = int(1).to_bytes(length=1, byteorder='big', signed=False)

    public_key_256 = bytes.fromhex(master_public_key_256)
    # 256-byte hash = 32-Bytes = 64 Hex Chars
    key_sha256 = hashlib.new("sha256", public_key_256).digest()
    # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
    key_ripemd160 = hashlib.new("ripemd160", key_sha256).digest()
    parent_key_fingerprint = key_ripemd160[:4]    # first 32-bits 4-bytes
    # child_number = int(0).to_bytes(length=4, byteorder='big', signed=False)

    xprv = depth + parent_key_fingerprint + hardened_index_num + \
        child_chain_code_256 + b"\x00" + new_child_priv_key_256

    xprv_hex = xprv.hex()
    xprv_base58 = cbl.Base58.check_encode(
        s_hex=xprv_hex, version_prefix=cbl.Prefix.BIP_32_EXTENDED_PRIVATE_KEY)
    print(f'xprv_base58: {xprv_base58}')

    # xpub
    keys.private_key = int.from_bytes(
        bytes=new_child_priv_key_256, byteorder='big', signed=False)
    keys.generate_public_key()
    child_public_key_256 = keys.get_public_key_compressed_hex()
    child_public_key_256 = bytes.fromhex(child_public_key_256)
    xpub = depth + parent_key_fingerprint + hardened_index_num + \
        child_chain_code_256 + child_public_key_256
    xpub_hex = xpub.hex()
    xpub_base58 = cbl.Base58.check_encode(
        s_hex=xpub_hex, version_prefix=cbl.Prefix.BIP_32_EXTENDED_PUBLIC_KEY)
    print(f'xpub_base58: {xpub_base58}')

    # # M/0'/0'
    # print("-" * 120 + "\n* m/0'/0'\n" + "-" * 120)
    # parent_priv_key = new_child_priv_key_256
    # parent_chain_code = child_chain_code_256
    # index_num = 0
    # hardened_index = 2**31
    # hardened_index_num = (index_num + hardened_index).to_bytes(length=4,
    #                                                            byteorder='big', signed=False)
    # hash_input = b"\x00" + parent_priv_key + hardened_index_num
    # hmac_sha512 = hmac.new(key=parent_chain_code,
    #                        msg=hash_input,
    #                        digestmod=hashlib.sha512).digest()
    # child_priv_key_256 = hmac_sha512[:32]  # Left 256-bits
    # parent_priv_key_int = int.from_bytes(
    #     bytes=parent_priv_key, byteorder='big', signed=False)
    # child_priv_key_int = int.from_bytes(
    #     bytes=child_priv_key_256, byteorder='big', signed=False)
    # # _p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
    # n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # new_child_priv_key_int = int((child_priv_key_int + parent_priv_key_int) % n)
    # new_child_priv_key_256 = new_child_priv_key_int.to_bytes(
    #     length=32, byteorder='big', signed=False)

    # child_chain_code_256 = hmac_sha512[32:]   # Right 256-bits

    # depth = int(2).to_bytes(length=1, byteorder='big', signed=False)

    # # 256-byte hash = 32-Bytes = 64 Hex Chars
    # key_sha256 = hashlib.new("sha256", child_public_key_256).digest()
    # # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
    # key_ripemd160 = hashlib.new("ripemd160", key_sha256).digest()
    # parent_key_fingerprint = key_ripemd160[:4]    # first 32-bits 4-bytes
    # # child_number = int(0).to_bytes(length=4, byteorder='big', signed=False)

    # xprv = depth + parent_key_fingerprint + hardened_index_num + \
    #     child_chain_code_256 + b"\x00" + new_child_priv_key_256

    # xprv_hex = xprv.hex()
    # xprv_base58 = cbl.base58.b58check_encode(
    #     s_hex=xprv_hex, version_prefix=cbl.AddressPrefix.BIP_32_EXTENDED_PRIVATE_KEY)
    # print(f'xprv_base58: {xprv_base58}')

    # # xpub
    # keys.private_key = int.from_bytes(
    #     bytes=new_child_priv_key_256, byteorder='big', signed=False)
    # keys.generate_public_key()
    # child_public_key_256 = keys.get_public_key_compressed_hex()
    # child_public_key_256 = bytes.fromhex(child_public_key_256)
    # xpub = depth + parent_key_fingerprint + hardened_index_num + \
    #     child_chain_code_256 + child_public_key_256
    # xpub_hex = xpub.hex()
    # xpub_base58 = cbl.base58.b58check_encode(
    #     s_hex=xpub_hex, version_prefix=cbl.AddressPrefix.BIP_32_EXTENDED_PUBLIC_KEY)
    # print(f'xpub_base58: {xpub_base58}')

    pass


'''
new_xprv_base59 = 'xprv9vD6P73U5kDJqd2m4KdRS5FofTEnZBQxHRUZS9MuRiLdDp7ZBD8TQG9Y91q6TwQYw8wHf6wEcRXQF5XggKBymsxedD2S2DX7MLk7w8MEfXz'
new_xprv_hex = '0488ade401b226959280000000ce62c620b7cd66e27f970d0f29e4f2082c6b7740bd184d0c9c61f79d819af56300b002c1c5b7c3a9937c08e468fa0fba20ddd8a31a07deddf1464ac160fe9bd334a607b485'

version_4 = "0488ade4"
depth_1 = "01"
fingerprint_4 =  "b2269592"
child_num_4 = "80000000"
chain_code_32 = "ce62c620b7cd66e27f970d0f29e4f2082c6b7740bd184d0c9c61f79d819af563"
prv_key_33    = "00b002c1c5b7c3a9937c08e468fa0fba20ddd8a31a07deddf1464ac160fe9bd334"
check_sum_4 = "a607b485"
'''

''' Mine
new_xprv_base59 = 'xprv9vD6P73U5kDJqd2m4KdRS5FofTEnZBQxHRUZS9MuRiLdDp7ZBD8TQG9Y91q6TwQYw8wHf6wEcRXQF5Xc9Sq5ErhsAVmSmMooPsEydcxgtMW'
new_xprv_hex = '00b002c1c5b7c3a9937c08e468fa0fba1f98878000b7277e2d061d1feeced2184699451839'

version_4 = "0488ade4"
depth_1 = "01"
fingerprint_4 =  "b2269592"
child_num_4 = "80000000"
chain_code_32 = "ce62c620b7cd66e27f970d0f29e4f2082c6b7740bd184d0c9c61f79d819af563"
prv_key_33    = "00b002c1c5b7c3a9937c08e468fa0fba1f98878000b7277e2d061d1feeced21846"
check_sum_4 = "99451839"
'''

# bip32_root_key = 'xprv9s21ZrQH143K3t4UZrNgeA3w861fwjYLaGwmPtQyPMmzshV2owVpfBSd2Q7YsHZ9j6i6ddYjb5PLtUdMZn8LhvuCVhGcQntq5rn7JVMqnie'
# bip32_root_key_hex = '0488ade4000000000000000000b70d675323c40ec461e0a6af603b1f135fb2af9ae753eeff18922732a73b0f0500b2a0d576b828b537688b561f2cfa8dac3602d54c62bde619ad5331e6c235ee26d2f07343'
# bip32_root_key_payload_hex = '000000000000000000b70d675323c40ec461e0a6af603b1f135fb2af9ae753eeff18922732a73b0f0500b2a0d576b828b537688b561f2cfa8dac3602d54c62bde619ad5331e6c235ee26'

# bip32_root_key_base58 = cbl.base58.b58check_encode(
#     s_hex=bip32_root_key_payload_hex, version_prefix=cbl.AddressPrefix.BIP_32_EXTENDED_PRIVATE_KEY)
# print(f'bip32_root_key: {bip32_root_key}')
# print(f'bip32_root_key_base58: {bip32_root_key_base58}')


# entropy_hex = f'{entropy_int:x}'
# print(entropy_hex)

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
