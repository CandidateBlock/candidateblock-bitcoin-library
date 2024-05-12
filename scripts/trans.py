import copy
from typing import List

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

    def script_sig_p2pkh(signature: bytes, pubkey: bytes, sighash: int = SIGHASH_ALL) -> bytes:
        sec = pubkey
        der = signature
        der += int(sighash).to_bytes(length=1, byteorder='little', signed=False)
        # Output
        data = bytes()
        data += Tx.var_string(input=der)
        data += Tx.var_string(input=sec)
        return data

    def sighash_legacy(self, input_index, script_pubkey, sighash=SIGHASH_ALL):
        script_sig = bytes()
        script_sig += Tx.pay_to_pub_key_hash(
            address=cbl.Hashes.hash160(value=script_pubkey))

        # Copy TX stored in class, to override tx_ins[].script_sig for signing
        tx_to_sign = Tx()
        tx_to_sign.version = self.version
        tx_to_sign.has_witness = self.has_witness
        tx_to_sign.tx_ins = copy.deepcopy(self.tx_ins)
        tx_to_sign.tx_outs = self.tx_outs
        tx_to_sign.witness = self.witness
        tx_to_sign.lock_time = self.lock_time
        for i, inp in enumerate(self.tx_ins):
            # Are we signing this input with script_pubkey
            if input_index == i:
                new_tx_in = Tx_in(
                    prev_tx_out_hash=inp.prev_tx_out_hash,
                    prev_tx_out_index=inp.prev_tx_out_index,
                    script_sig=script_sig,
                    sequence=0xffffffff)
            else:
                # Not signing this input = empty script_sig
                new_tx_in = Tx_in(
                    prev_tx_out_hash=inp.prev_tx_out_hash,
                    prev_tx_out_index=inp.prev_tx_out_index,
                    script_sig=b"",
                    sequence=0xffffffff)
            tx_to_sign.tx_ins[i] = new_tx_in
        signing_bytes = tx_to_sign.serialization()
        signing_bytes += int(SIGHASH_ALL).to_bytes(length=4,
                                                   byteorder='little', signed=False)
        print(signing_bytes.hex())
        # Get Txid (double SHA256)
        hash, check_sum = cbl.Hashes.double_sha256(value=signing_bytes)
        return hash

    def sign(self, hash: bytes, pri_key: bytes, grind: bool = True):
        # New Sign transaction
        sig = cbl.py_secp256k1.ecdsa_sign(hash, pri_key)
        print(nice(name="SigNew1", input=sig))
        if grind:
            counter = 1
            while len(sig) > 70:
                sig = cbl.py_secp256k1.ecdsa_sign(
                    hash, pri_key, None, counter.to_bytes(32, 'little'))
                print(nice(name="SigNewX", input=sig))
                counter += 1
                # just in case we get in infinite loop for some reason
                if counter > 200:
                    break
        print(nice(name="SigNewF", input=sig))
        return sig


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
    cc0_testnet = "bitter opinion column spoon tip they cliff butter print test artwork expose"
    cc1_testnet = "front asthma oyster shoot view jungle matter either neither hope index file"

    derivation = "m/44'/1'/0'"
    correct_unsigned_trans_hex = bytes.fromhex(
        "0200000001bebbbfc955f90193b4be28e81ee3980212211a00de2c8fc87c003ff5b38eefc50000000000ffffffff01430a0000000000001976a914956729de96774428d4e4d82fb242ab504112f8b488ac00000000")
    correct_signed_trans = bytes.fromhex(
        "0200000001bebbbfc955f90193b4be28e81ee3980212211a00de2c8fc87c003ff5b38eefc5000000006a47304402201c0dbd540c1d9d9f2079b33e3e0db374f19269422a038f1bf54e7ded8e8d66fa0220212a8a3f0cebec78cb12c3ed9fc21fa65d6cf055ea9a8309e17de36aeadc375801210399fb50578b99104c6d6f55351d918998f0a12746b094db5fa15b36ab64c76021ffffffff01430a0000000000001976a914956729de96774428d4e4d82fb242ab504112f8b488ac00000000")
    correct_txid = bytes.fromhex(
        "ce751350d16ca732b6acdc70361ac15c20fd4aaf82ce5b6bff51ccf40b538f49")

    print(title(name="Main"))
    seed_cc0 = cbl.Mnemonic.mnemonic_to_seed(
        mnemonic_sentence=cc0_testnet, passphrase="")
    seed_cc1 = cbl.Mnemonic.mnemonic_to_seed(
        mnemonic_sentence=cc1_testnet, passphrase="")

    # *** Inputs
    # Get Spending Address 0
    full_path = derivation + "/0/3"
    spend_pri_key_0 = derive_path(seed=seed_cc0, path=full_path)
    spend_pub_key_0 = cbl.Keys.generate_pub_key(
        priv_key=spend_pri_key_0, is_compressed=True)

    # # Get Spending Address 1
    # full_path = derivation + "/0/1"
    # spend_pri_key_1 = derive_path(seed=seed_cc0, path=full_path)
    # spend_pub_key_1 = cbl.Keys.generate_pub_key(
    #     priv_key=spend_pri_key_1, is_compressed=True)

    # # *** Outputs
    # # Get receiving address 0 = Change Address
    # full_path = derivation + "/1/0"
    # change_pri_key_0 = derive_path(seed=seed_nunchuk, path=full_path)
    # change_pub_key_0 = cbl.Keys.generate_pub_key(
    #     priv_key=change_pri_key_0, is_compressed=True)

    # # Get receiving address 0
    # full_path = derivation + "/0/2"
    # receiving_pri_key_0 = derive_path(seed=seed_cc1, path=full_path)
    # receiving_pub_key_0 = cbl.Keys.generate_pub_key(
    #     priv_key=receiving_pri_key_0, is_compressed=True)

    # Set receiving address 0
    receiving_pub_key_0_address = "mu8vZZnTqcW1k6hhgnyQB6anNC8vvCF7sq"
    receiving_pub_key_0_hash160 = bytes.fromhex(
        "956729de96774428d4e4d82fb242ab504112f8b4")

    print(title(name="Unsigned Transaction"))
    tx = Tx(version=2)

    # Create Input 0 (2780)
    script_sig = None
    tx_in = Tx_in(
        prev_tx_out_hash=0xc5ef8eb3f53f007cc88f2cde001a21120298e31ee828beb49301f955c9bfbbbe,
        prev_tx_out_index=0,
        script_sig=script_sig,
        sequence=0xffffffff)
    tx.tx_ins.append(tx_in)

    # # Create Input 1 (4808)
    # script_sig = None
    # tx_in = Tx_in(
    #     prev_tx_out_hash=0x77dd7f23e38d173189865898a0295da0c61a01e81850cf4f271730266c63cf08,
    #     prev_tx_out_index=0,
    #     script_sig=script_sig,
    #     sequence=0xffffffff)
    # tx.tx_ins.append(tx_in)

    # Create an Output 1 - Payment
    tx_out = Tx_out(
        value_in_sats=2627,
        script_pub_key=Tx.pay_to_pub_key_hash(address=receiving_pub_key_0_hash160))
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
    for i, tx_in in enumerate(tx.tx_ins):
        if i == 0:
            script_prikey = spend_pri_key_0
            script_pubkey = spend_pub_key_0
        else:
            pass
            # script_prikey = spend_pri_key_1
            # script_pubkey = spend_pub_key_1

        hash = tx.sighash_legacy(input_index=i, script_pubkey=script_pubkey)
        sig = tx.sign(hash=hash, pri_key=script_prikey, grind=True)
        tx_in.script_sig = Tx.script_sig_p2pkh(
            signature=sig, pubkey=script_pubkey, sighash=SIGHASH_ALL)

    print(title(name="Finalised Transaction"))
    print(tx.serialization().hex())
    print(nice(name="Txid le", input=tx.get_txid()))
    assert tx.serialization() == correct_signed_trans
    assert tx.get_txid() == correct_txid
