import hashlib
from typing import List

import ecdsa

import candidateblock_bitcoin_library as cbl

# https://en.bitcoin.it/wiki/Transaction

OP_DUP = b'\x76'
OP_HASH160 = b'\xa9'
OP_EQUALVERIFY = b'\x88'
OP_CHECKSIG = b'\xac'

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

SATS_PER_BTC = 100000000


def title(name: str) -> None:
    CHARS = 120
    txt = "\n"
    txt += "*" * CHARS
    txt += "\n"
    txt += "* " + name + " "
    txt += "*" * (CHARS - len(name) - 3)
    txt += "\n"
    txt += "*" * CHARS
    return txt


def nice(name: str, input: bytes) -> None:
    return f"{name}: ({len(input)}|{len(input)*8}) {input.hex()}"


class Tx_in:
    def __init__(self, prev_tx_out_hash: bytes, prev_tx_out_index: int, script_sig: bytes = None, sequence: int = 0xffffffff):
        self.prev_tx_out_hash = prev_tx_out_hash
        self.prev_tx_out_index = prev_tx_out_index
        self.script_sig = script_sig
        self.sequence = sequence

    def serialization(self):
        tx_bytes = bytes()
        tx_bytes += self.prev_tx_out_hash.to_bytes(
            length=32, byteorder='little', signed=False)
        tx_bytes += self.prev_tx_out_index.to_bytes(
            length=4, byteorder='little', signed=False)
        if self.script_sig is None:
            tx_bytes += Tx.var_int(num=0)
        else:
            tx_bytes += Tx.var_int(num=len(self.script_sig))
            tx_bytes += self.script_sig
        tx_bytes += self.sequence.to_bytes(length=4, byteorder='little', signed=False)
        return tx_bytes


class Tx_out:
    def __init__(self, value_in_sats: int, script_pub_key: bytes = None):
        self.value_in_sats = value_in_sats
        self.script_pub_key = script_pub_key

    def serialization(self):
        tx_bytes = bytes()
        tx_bytes += self.value_in_sats.to_bytes(length=8,
                                                byteorder='little', signed=False)
        if self.script_pub_key is None:
            tx_bytes += Tx.var_int(num=0)
        else:
            tx_bytes += Tx.var_int(num=len(self.script_pub_key))
            tx_bytes += self.script_pub_key
        return tx_bytes


class Tx:
    def __init__(self, version: int = 1, has_witness: bool = False, tx_ins: List[Tx_in] = [], tx_outs: List[Tx_out] = [], witness: bytes = None, lock_time: int = 0):
        self.version = version
        self.has_witness = has_witness
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.witness = witness
        self.lock_time = lock_time

    def serialization(self):
        tx_bytes = bytes()
        if self.has_witness is True:
            # TODO - Fix seg witness
            return tx_bytes
        # Version
        tx_bytes += self.version.to_bytes(length=4, byteorder='little', signed=False)
        # Inputs
        if self.tx_ins:
            num_inputs = len(self.tx_ins)
        else:
            num_inputs = 0
        tx_bytes += Tx.var_int(num=num_inputs)
        for tx_in in self.tx_ins:
            tx_bytes += tx_in.serialization()
        # Outputs
        if self.tx_outs:
            num_outputs = len(self.tx_outs)
        else:
            num_outputs = 0
        tx_bytes += Tx.var_int(num=num_outputs)
        for tx_out in self.tx_outs:
            tx_bytes += tx_out.serialization()
        # Locktime
        tx_bytes += self.lock_time.to_bytes(length=4, byteorder='little', signed=False)
        return tx_bytes

    def get_txid(self):
        #  Txid (double SHA256)
        hash, check_sum = cbl.Hashes.double_sha256(value=self.serialization())
        return hash[::-1]  # little endian vs big endian encodings

    @staticmethod
    def var_int(num: int) -> bytes:
        if num < 0xfd:
            ret = num.to_bytes(length=1, byteorder='little', signed=False)
        elif num <= 0xffff:
            ret = b'\xfd' + num.to_bytes(length=2, byteorder='little', signed=False)
        elif num <= 0xffffffff:
            ret = b'\xfe' + num.to_bytes(length=4, byteorder='little', signed=False)
        elif num <= 0xffffffffffffffff:
            ret = b'\xff' + num.to_bytes(length=8, byteorder='little', signed=False)
        else:
            raise ValueError(f"integer too large (8-Bytes max): {num}")

        return ret

    @staticmethod
    def var_string(input: bytes) -> bytes:
        return Tx.var_int(num=len(input)) + input

    @staticmethod
    def pay_to_pub_key_hash(address: bytes) -> bytes:
        script_pub_key = bytes()
        script_pub_key += OP_DUP
        script_pub_key += OP_HASH160
        script_pub_key += Tx.var_string(input=address)
        script_pub_key += OP_EQUALVERIFY
        script_pub_key += OP_CHECKSIG
        return script_pub_key

    @staticmethod
    def pay_to_script_hash(address: bytes) -> bytes:
        pass


def derive_path(seed: bytes, path: str):
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

    # Private to Public Key
    is_private = False
    new_public_key = cbl.Keys.generate_pub_key(
        priv_key=child_ext_key, is_compressed=True)
    new_xpub = cbl.HdWallet.encode(key=new_public_key, chain_code=child_chain_code, parent_key=parent_key,
                                   depth=depth, child=index, is_master=is_master, is_private=is_private, is_mainnet=is_mainnet)
    print(f"depth: {depth} | index: {str_index} | xpub: {new_xpub}")

    # Print Leaf
    wif = cbl.Keys.priv_key_wif_encode(
        priv_key=child_ext_key, is_compressed=True, is_mainnet=is_mainnet)
    address = cbl.Keys.btc_address_p2pkh(pub_key=new_public_key, is_mainnet=is_mainnet)
    public_key_hash160 = cbl.Hashes.hash160(value=new_public_key)
    print(">" * 3 + " Leaf")
    print(f"address:                   {address}")
    print(f"Public  Key         (HEX): {new_public_key.hex()}")
    print(f"Public  Key Hash160 (HEX): {public_key_hash160.hex()}")
    print(f"Private Key         (WIF): {wif}")
    print(f"Private Key         (HEX): {child_ext_key.hex()}")
    return child_ext_key


if __name__ == "__main__":
    sparrow_testnet = "wear snow pluck roast dilemma develop attend stock naive squeeze pigeon rose"
    nunchuk_testnet = "under pause uncover flat pole candy also sure curious dizzy choose minimum"

    derivation = "m/44'/1'/0'"
    correct_unsigned_trans_hex = bytes.fromhex(
        "020000000108cf636c263017274fcf5018e8011ac6a05d29a09858868931178de3237fdd770000000000ffffffff0108120000000000001976a91444afd3d7638352df84d7112f2e98038620080dc188ac00000000")
    correct_signed_trans = bytes.fromhex(
        "0200000002d4680233780a55dcb2da78881c1ce62216400ca1d6d7c2d804ac04c89976b596000000006a47304402200769e828a0edf2fbbc2fa89fdddbdd83950d2698342f93b56c3868ffe1740aef02204bf106f29922178f45d9cf8cd427a73579fb5698834d1f31cff47a61a713d5a8012102c0c42a8154426866d003de54d89e6e09deb19ccb169a5bd0056e56c05c2140f6ffffffffe47d537eed9c4301ab7f2966f6facbdafe4f17e6b9cf21c120ed4b3f5b548dde000000006a47304402205278bd6dfbb143f820782a9803045b52e8e5bda9b8dd7250a30205986a5875420220496aea89ec41857572ce0a9077484bff9e8ca0c3d9e40cc5c460ab0b5ea9ef5c0121034a741361c6c4fb4ccc28177996be30eecd2441fea8591dab7bcb1ae7a07c37cdffffffff020f020000000000001976a9141a42b77a5531eee28e02d1c96b56c4643733497688acec130000000000001976a9144b8ff26577f5ea1ec25bc441481100c5ef2be3ba88ac00000000")
    correct_txid = bytes.fromhex(
        "cf111fe7241a62d2c9cea8e0886ead17c65f34f9e83cb44214ff9bd96fe997bb")

    print(title(name="Main"))
    seed_sparrow = cbl.Mnemonic.mnemonic_to_seed(
        mnemonic_sentence=sparrow_testnet, passphrase="")
    seed_nunchuk = cbl.Mnemonic.mnemonic_to_seed(
        mnemonic_sentence=nunchuk_testnet, passphrase="")

    # *** Inputs
    # Get Spending Address 0
    full_path = derivation + "/0/1"
    spend_pri_key_0 = derive_path(seed=seed_sparrow, path=full_path)
    spend_pub_key_0 = cbl.Keys.generate_pub_key(
        priv_key=spend_pri_key_0, is_compressed=True)

    # # Get Spending Address 1
    # full_path = derivation + "/0/1"
    # spend_pri_key_1 = derive_path(seed=seed_nunchuk, path=full_path)
    # spend_pub_key_1 = cbl.Keys.generate_pub_key(
    #     priv_key=spend_pri_key_1, is_compressed=True)

    # # *** Outputs
    # # Get receiving address 0 = Change Address
    # full_path = derivation + "/1/0"
    # change_pri_key_0 = derive_path(seed=seed_nunchuk, path=full_path)
    # change_pub_key_0 = cbl.Keys.generate_pub_key(
    #     priv_key=change_pri_key_0, is_compressed=True)

    # Get receiving address 0
    full_path = derivation + "/0/2"
    receiving_pri_key_0 = derive_path(seed=seed_nunchuk, path=full_path)
    receiving_pub_key_0 = cbl.Keys.generate_pub_key(
        priv_key=receiving_pri_key_0, is_compressed=True)

    print(title(name="Unsigned Transaction"))
    tx = Tx(version=2)

    # Create Input 1 (4808)
    script_sig = None
    tx_in = Tx_in(
        prev_tx_out_hash=0x77dd7f23e38d173189865898a0295da0c61a01e81850cf4f271730266c63cf08,
        prev_tx_out_index=0,
        script_sig=script_sig,
        sequence=0xffffffff)
    tx.tx_ins.append(tx_in)

    # # Create Input 2 (1000)
    # script_sig = None
    # tx_in = Tx_in(
    #     prev_tx_out_hash=0xde8d545b3f4bed20c121cfb9e6174ffedacbfaf666297fab01439ced7e537de4,
    #     prev_tx_out_index=0,
    #     script_sig=script_sig,
    #     sequence=0xffffffff)
    # tx.tx_ins.append(tx_in)

    # Create an Output 1 - Payment
    tx_out = Tx_out(
        value_in_sats=4616,
        script_pub_key=Tx.pay_to_pub_key_hash(address=cbl.Hashes.hash160(value=receiving_pub_key_0)))
    tx.tx_outs.append(tx_out)
    # # Create an Output 2 - Payment
    # tx_out = Tx_out(
    #     value_in_sats=5100,
    #     script_pub_key=Tx.pay_to_pub_key_hash(address=cbl.Hashes.hash160(value=receiving_pub_key_0)))
    # tx.tx_outs.append(tx_out)

    print(tx.serialization().hex())
    # Correct Hex
    assert tx.serialization() == correct_unsigned_trans_hex

    print(title(name="Transaction Ready for Siging"))
    script_sig = bytes()
    script_sig += Tx.pay_to_pub_key_hash(
        address=cbl.Hashes.hash160(value=spend_pub_key_0))
    tx_in_signed = Tx_in(
        prev_tx_out_hash=tx.tx_ins[0].prev_tx_out_hash,
        prev_tx_out_index=tx.tx_ins[0].prev_tx_out_index,
        script_sig=script_sig,
        sequence=0xffffffff)
    tx.tx_ins[0] = tx_in_signed
    signing_bytes = tx.serialization()
    signing_bytes += int(SIGHASH_ALL).to_bytes(length=4,
                                               byteorder='little', signed=False)
    print(signing_bytes.hex())
    # Check Txid (double SHA256)
    hash, check_sum = cbl.Hashes.double_sha256(value=signing_bytes)
    # print(nice(name="Txid be", input=hash))
    # assert hash == bytes.fromhex(
    #     "569e326a8cb13bf3f02e9010b17bc3ff8c9b820f3fd6c8a8332af7f99b7189ff")

    # Set keys and Sign Txid
    sk = ecdsa.SigningKey.from_string(
        string=spend_pri_key_0, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    print(nice(name="sk     ", input=sk.to_string()))
    assert sk.to_string() == spend_pri_key_0

    vk = sk.verifying_key
    print(nice(name="vk     ", input=vk.to_string()))
    print(nice(name="vk Comp", input=vk.to_string("compressed")))

    sig = sk.sign_digest_deterministic(
        digest=hash, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der, extra_entropy=b"", allow_truncate=False)
    print(nice(name="SigOld1", input=sig))

    # In Bitcoin to save two bytes
    # DER of signature can not be > 70 bytes long
    # use counter as extra entropy until <= 70 bytes long
    # 71-byte, 72-byte, and 73-byte-signatures can be observed.
    # Basically the DER schema for encoding ECDSA signed messages puts an extra
    # byte 0x00 infront of the 32-Byte R & S number of the most significant bit
    # of R & S is set - as this means signed interger (which is confusing).
    counter = 1
    while len(sig) > 70:
        extra_entropy = counter.to_bytes(length=32, byteorder='little', signed=False)
        sig = sk.sign_digest_deterministic(
            digest=hash, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der, extra_entropy=extra_entropy, allow_truncate=False)
        print(nice(name="SigOldX", input=sig))
        counter += 1
        # just in case we get in infinite loop for some reason
        if counter > 200:
            break
    print(nice(name="SigOldF", input=sig))

    assert vk.verify_digest(signature=sig, digest=hash,
                            sigdecode=ecdsa.util.sigdecode_der, allow_truncate=False) is True

    # correct_sig_der = bytes.fromhex(
    #     "304402201903ca8e1c52e861dc57bee84bd67273f25b88270ba95c974dcab651de08a05f02206044d68b732d88446e6c374b38ffe3bb74d2c04ba6919e93b4927b7cde7a26ea")
    # print(nice(name="corsder", input=correct_sig_der))
    # assert sig == correct_sig_der

    # New Sig routine
    grind = True
    sig = cbl.py_secp256k1.ecdsa_sign(hash, spend_pri_key_0)
    print(nice(name="SigNew1", input=sig))
    if grind:
        counter = 1
        while len(sig) > 70:
            sig = cbl.py_secp256k1.ecdsa_sign(
                hash, spend_pri_key_0, None, counter.to_bytes(32, 'little'))
            print(nice(name="SigNewX", input=sig))
            counter += 1
            # just in case we get in infinite loop for some reason
            if counter > 200:
                break
    print(nice(name="SigNewF", input=sig))

    print(title(name="Signed Transaction"))
    # Update Txin for correctly signed data
    final = sig
    final += SIGHASH_ALL.to_bytes(length=1, byteorder='little', signed=False)
    script_sig = bytes()
    script_sig += Tx.var_int(num=len(final))
    script_sig += final
    script_sig += Tx.var_int(num=len(spend_pub_key_0))
    script_sig += spend_pub_key_0
    tx_in = Tx_in(
        prev_tx_out_hash=tx.tx_ins[0].prev_tx_out_hash,
        prev_tx_out_index=tx.tx_ins[0].prev_tx_out_index,
        script_sig=script_sig,
        sequence=0xffffffff)
    tx.tx_ins[0] = tx_in
    print(nice(name="FinalTX", input=tx.serialization()))
    print(nice(name="Txid le", input=tx.get_txid()))
    assert tx.serialization() == correct_signed_trans
    assert tx.get_txid() == correct_txid

'''
0200000002d4680233780a55dcb2da78881c1ce62216400ca1d6d7c2d804ac04c89976b5960000000000ffffffffe47d537eed9c4301ab7f2966f6facbdafe4f17e6b9cf21c120ed4b3f5b548dde0000000000ffffffff0288130000000000001976a9144b8ff26577f5ea1ec25bc441481100c5ef2be3ba88acf4010000000000001976a9141a42b77a5531eee28e02d1c96b56c4643733497688ac00000000
0200000002d4680233780a55dcb2da78881c1ce62216400ca1d6d7c2d804ac04c89976b5960000000000ffffffffe47d537eed9c4301ab7f2966f6facbdafe4f17e6b9cf21c120ed4b3f5b548dde0000000000ffffffff020f020000000000001976a9141a42b77a5531eee28e02d1c96b56c4643733497688acec130000000000001976a9144b8ff26577f5ea1ec25bc441481100c5ef2be3ba88ac00000000
'''
