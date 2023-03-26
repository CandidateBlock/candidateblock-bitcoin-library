import hashlib
from typing import List, Union

import ecdsa

import candidateblock_bitcoin_library as cbl

# https://en.bitcoin.it/wiki/Transaction

OP_DUP = b'\x76'
OP_HASH160 = b'\xa9'
OP_EQUALVERIFY = b'\x88'
OP_CHECKSIG = b'\xac'

SIGHASH_ALL = b'\x01'

SATS_PER_BTC = 100000000


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


def var_string(input: bytes) -> bytes:
    return var_int(num=len(input)) + input


def pay_to_pub_key_hash(address: bytes) -> bytes:
    script_pub_key = bytes()
    script_pub_key += OP_DUP
    script_pub_key += OP_HASH160
    script_pub_key += var_string(input=address)
    script_pub_key += OP_EQUALVERIFY
    script_pub_key += OP_CHECKSIG
    return script_pub_key


def pay_to_script_hash(address: bytes) -> bytes:
    pass


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
            tx_bytes += var_int(num=0)
        else:
            tx_bytes += var_int(num=len(self.script_sig))
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
            tx_bytes += var_int(num=0)
        else:
            tx_bytes += var_int(num=len(self.script_pub_key))
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
        tx_bytes += var_int(num=num_inputs)
        for tx_in in self.tx_ins:
            tx_bytes += tx_in.serialization()
        # Outputs
        if self.tx_outs:
            num_outputs = len(self.tx_outs)
        else:
            num_outputs = 0
        tx_bytes += var_int(num=num_outputs)
        for tx_out in self.tx_outs:
            tx_bytes += tx_out.serialization()
        # Locktime
        tx_bytes += self.lock_time.to_bytes(length=4, byteorder='little', signed=False)
        return tx_bytes


if __name__ == "__main__":
    print("*" * 120 + "\n* Transaction\n" + "*" * 120)

    tx = Tx()

    # Create an Input
    signature = bytes.fromhex(
        "3045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e3813")
    # Uncompressed 0x04 = 512-Bits = 64-Bytes
    pub_key = bytes.fromhex(
        "0484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf")
    script_sig = bytes()
    script_sig += var_int(num=len(signature + SIGHASH_ALL))
    script_sig += signature
    script_sig += SIGHASH_ALL
    script_sig += var_int(num=len(pub_key))
    script_sig += pub_key
    tx_in = Tx_in(
        prev_tx_out_hash=0x7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18,
        prev_tx_out_index=0,
        script_sig=script_sig,
        sequence=0xffffffff)
    tx.tx_ins.append(tx_in)

    # Create an Output 1
    address = bytes.fromhex("ab68025513c3dbd2f7b92a94e0581f5d50f654e7")
    tx_out = Tx_out(
        value_in_sats=1500000,
        script_pub_key=pay_to_pub_key_hash(address=address))
    tx.tx_outs.append(tx_out)

    # Create an Output 2
    address = bytes.fromhex("7f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a8")
    tx_out = Tx_out(
        value_in_sats=8450000,
        script_pub_key=pay_to_pub_key_hash(address=address))
    tx.tx_outs.append(tx_out)

    # Serialize the Transcation
    print(tx.serialization().hex())

    # Correct Hex
    correct_hex = bytes.fromhex("0100000001186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779000000008b483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adfffffffff0260e31600000000001976a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788acd0ef8000000000001976a9147f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a888ac00000000")
    assert tx.serialization() == correct_hex

'''
    # Version
    version = int(1).to_bytes(length=4, byteorder='little', signed=False)
    # Input Count
    input_count = var_int(num=1)
    # Inputs
    # Input 1
    txid = int(0x1f4ff528e85fb738413b5c1cad15a3dd245f695057f96ad05c9b2b6ea4f7e066).to_bytes(
        length=32, byteorder='little', signed=False)
    vout = int(1).to_bytes(length=4, byteorder='little', signed=False)
    scriptsig = b''
    scriptsig_size = var_int(num=0)
    sequence = int(0xffffffff).to_bytes(length=4, byteorder='little', signed=False)
    # Inputs
    inputs = input_count
    inputs += txid
    inputs += vout
    inputs += scriptsig_size
    inputs += scriptsig
    inputs += sequence
    # Output Count
    output_count = var_int(num=1)
    # Output 1
    amount = 10000
    fee = 200
    net = amount - fee
    value = int(net).to_bytes(length=8, byteorder='little', signed=False)
    # scriptpubkey = bytes.fromhex("00142045a28be0ccca8c3aa0a8c099aa9ea642f1f9fa")
    # scriptpubkey_size = var_int(num=len(scriptpubkey))

    pub_key = "mnQVR3Y3z28hDSwYGmbkmUG8WbVLriqrc7"
    data = cbl.Base58.check_decode(b58=pub_key)
    address_prefix, payload, checksum = data

    scriptpubkey = OP_DUP
    scriptpubkey += OP_HASH160
    scriptpubkey += var_int(num=len(payload))
    scriptpubkey += payload
    scriptpubkey += OP_EQUALVERIFY
    scriptpubkey += OP_CHECKSIG
    scriptpubkey_size = var_int(num=len(scriptpubkey))

    # Outputs
    outputs = output_count
    outputs += value
    outputs += scriptpubkey_size
    outputs += scriptpubkey
    # Locktime
    locktime = int(0).to_bytes(length=4, byteorder='little', signed=False)

    # Transaction Byte Sequence
    unsigned_trans = version
    unsigned_trans += inputs
    unsigned_trans += outputs
    unsigned_trans += locktime
    print(unsigned_trans.hex())

    unsigned_sparrow = bytes.fromhex(
        "010000000166e0f7a46e2b9b5cd06af95750695f24dda315ad1c5c3b4138b75fe828f54f1f0100000000ffffffff0148260000000000001976a9144b8ff26577f5ea1ec25bc441481100c5ef2be3ba88ac00000000")
    print(unsigned_sparrow.hex())

    assert unsigned_sparrow == unsigned_trans

    # To sign the transaction
    # when we are serializing the transaction input that we wish to sign,
    # the rule is to replace the encoding of the script_sig (which we don’t have,
    # because again we’re just trying to produce it…) with the script_pubkey of the
    # transaction output this input is pointing back to. All other transaction
    # input’s script_sig is also replaced with an empty script, because those
    # inputs can belong to many other owners who can individually and independently
    # contribute their own signatures.

    # address: mxfyzeVAorciyEiAHYbc7D2rEjiMZYXGB3
    # Public Key (HEX): 03f2eac3976b9d90cae5df9c6d7809abbd1fd26e4e27a378406b33995fb5769f3c
    # Private Key (WIF): cQFQrn83iqW9hr8SDTzA4WZRyJo4UMhtGBZXaCFgwFXsfhKV9SET
    # Private Key (HEX): 4f96c5a6f152b7b9194430776fb543d1f23d3fb728e39cc03139725317bea82f
    private_key = bytes.fromhex(
        "4f96c5a6f152b7b9194430776fb543d1f23d3fb728e39cc03139725317bea82f")
    public_key = cbl.Keys.generate_pub_key(priv_key=private_key, is_compressed=True)
    public_key_addresss = cbl.Keys.btc_address_p2pkh(
        pub_key=public_key, is_mainnet=False)
    public_key_hash160 = cbl.BtcHash.hash160(value=public_key)

    scriptsig = public_key_hash160
    scriptsig_size = var_int(num=len(scriptsig))

    # Inputs
    inputs = input_count
    inputs += txid
    inputs += vout
    inputs += scriptsig_size
    inputs += scriptsig
    inputs += sequence

    # Transaction Byte Sequence
    trans = version
    trans += inputs
    trans += outputs
    trans += locktime
    print(trans.hex())

    # Now we can sign with our private key (owned from last transaction)
    sk = ecdsa.SigningKey.from_string(string=private_key, curve=ecdsa.SECP256k1)
    public_key_uncompressed = cbl.Keys.generate_pub_key(
        priv_key=private_key, is_compressed=False)
    vk = sk.verifying_key
    assert (b'\04' + vk.to_string()) == public_key_uncompressed
    # Trans + SIGHASH_ALL
    trans_hash, check_sum = cbl.BtcHash.double_sha256(
        value=trans + int(1).to_bytes(length=4, byteorder='little', signed=False))
    # signature = sk.sign_digest(digest=trans_hash, sigencode=ecdsa.util.sigencode_der)
    # signature = sk.sign_digest(digest=trans_hash, sigencode=ecdsa.util.sigencode_der_canonize)
    signature = sk.sign_digest_deterministic(
        digest=trans_hash, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)

    scriptsig = b''
    scriptsig += var_int(num=len(signature) + 1)
    scriptsig += signature
    scriptsig += SIGHASH_ALL
    scriptsig += var_int(num=len(public_key))
    scriptsig += public_key
    scriptsig_size = var_int(num=len(scriptsig))

    # Correct values
    ok = bytes.fromhex("473044022063c8ef5e5ef681845c82c30a6da84bf9ae236f01f6b285ee062ff248b39a99500220273f382651e4e5539ecaf7a8937a44294a9d0d6878285a55a0ca786867d5798a012103f2eac3976b9d90cae5df9c6d7809abbd1fd26e4e27a378406b33995fb5769f3c")
    ok_sig = ok[:ok[0] + 1]
    ok_pub_key = ok[-34:]
    print("-" * 120)
    print(f"scriptsig: {ok.hex(): <20}")
    print(f"sig: {ok_sig.hex(): <20}")
    print(f"PubKey: {ok_pub_key.hex(): <20}")

    # Inputs
    inputs = input_count
    inputs += txid
    inputs += vout
    inputs += scriptsig_size
    inputs += scriptsig
    inputs += sequence

    # Transaction Byte Sequence
    trans = version
    trans += inputs
    trans += outputs
    trans += locktime
    print(trans.hex())

    sparrow_signed = bytes.fromhex("010000000166e0f7a46e2b9b5cd06af95750695f24dda315ad1c5c3b4138b75fe828f54f1f010000006a473044022063c8ef5e5ef681845c82c30a6da84bf9ae236f01f6b285ee062ff248b39a99500220273f382651e4e5539ecaf7a8937a44294a9d0d6878285a55a0ca786867d5798a012103f2eac3976b9d90cae5df9c6d7809abbd1fd26e4e27a378406b33995fb5769f3cffffffff0148260000000000001976a9144b8ff26577f5ea1ec25bc441481100c5ef2be3ba88ac00000000")

    print(sparrow_signed == trans)
    pass
'''


'''
LSig    47
0x30    30
Lrs     44
0x02    02
Lr      20 
Sigr    63c8ef5e5ef681845c82c30a6da84bf9ae236f01f6b285ee062ff248b39a9950
0x02    02
Ls      20
Sigs    273f382651e4e5539ecaf7a8937a44294a9d0d6878285a55a0ca786867d5798a
0x01    01
'''

'''
LSig    48    
0x30    30 Start
lrs     45
0x02    02 Integer
lr      21 (33 bytes)
Sigr    00ac1d347347d9de42965c8945e96bec43a6279caf48af8c57c156df8a88f672ef
0x02    02 Integer
ls      20 (32 bytes)
Sigs    7e0886b0cad1dd15c727b7c2459afe2c4699c8a1fc75c4628a26ba364a224acb
0x01    01
'''
