import candidateblock_bitcoin_library as cbl

if __name__ == "__main__":
    print("*" * 120 + "\n* Wallet\n" + "*" * 120)

    # 12 Words use 16-Bytes, 128-Bit entropy
    sparrow_testnet = "wear snow pluck roast dilemma develop attend stock naive squeeze pigeon rose"
    seed = cbl.Mnemonic.mnemonic_to_seed(
        mnemonic_sentence=sparrow_testnet, passphrase="")
    assert seed == bytes.fromhex(
        '47c8c993c18b8480c78e5925ab70322c98d4f3eae68b9033bb175b6d6a1dc9bc7a001f1cef3821af3df42a42b7913081782164ca6ff064a4d9cf2911306776c7')

    path = "m/44'/1'/0'/0/0"
    print(f"path: {path}")
    path_array = cbl.HdWallet.parse_path(path=path)
    print(f"path_array: {path_array}")

    child_ext_key = b''
    child_chain_code = b''
    for element in path_array:
        depth = element[0]
        index = element[1]
        is_private = True
        is_mainnet = False
        # Update parent for next loop
        parent_key = child_ext_key
        parent_chaincode = child_chain_code
        if depth == 0:
            # Master node
            is_master = True
            child_ext_key, child_chain_code, master_fingerprint = cbl.HdWallet.master_key_generation(
                seed=seed)
            print(f'Master Fingerprint: {master_fingerprint.hex()}')
            index = 0
        else:
            # child node
            is_master = False

            child_ext_key, child_chain_code = cbl.HdWallet.child_key_derivation(
                parent_key=parent_key, parent_chaincode=parent_chaincode, index=index, is_private=is_private)

        new_xprv = cbl.HdWallet.encode(key=child_ext_key, chain_code=child_chain_code, parent_key=parent_key,
                                       depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
        if index >= 0x80000000:
            str_index = str(index - 0x80000000) + 'h'
        else:
            str_index = str(index)
        print(f"depth: {depth} | index: {str_index} | xprv: {new_xprv}")
    # assert "tprv8g5rVr2zQzTvibuo1AsHxqFRPL337JFqYD4idspqP7rC61ixBs2dKQtD8QPX9ZeFiZXEAt1NEjRTjbztVB6EJf1Q4KCmAjTMv3E8GExGBww" == new_xprv

    # Public to Private Key
    is_private = False
    new_public_key = cbl.Keys.generate_pub_key(
        priv_key=child_ext_key, is_compressed=True)
    new_xpub = cbl.HdWallet.encode(key=new_public_key, chain_code=child_chain_code, parent_key=parent_key,
                                   depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
    print(f"depth: {depth} | index: {str_index} | xpub: {new_xpub}")
    # assert "tpubDCmteG5EZN9bc4watpXtNEuXxMYyGdSk7WfVvPs8oPeavVyipFrDVuW5JZriA924UgXrHfiXJK4N7GVtMZeqEeeRiqCjNvNVR2XcRnvshsV" == new_xpub

    # Print root
    wif = cbl.Keys.priv_key_wif_encode(
        priv_key=child_ext_key, is_compressed=True, is_mainnet=is_mainnet)
    address = cbl.Keys.btc_address_p2pkh(pub_key=new_public_key, is_mainnet=is_mainnet)
    print(">" * 3 + " Root")
    print(f"address: {address}")
    print(f"Public Key (HEX): {new_public_key.hex()}")
    print(f"Private Key (WIF): {wif}")
    print(f"Private Key (HEX): {child_ext_key.hex()}")
