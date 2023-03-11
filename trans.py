import hashlib

import ecdsa

import candidateblock_bitcoin_library as cbl

OP_DUP = b'\x76'
OP_HASH160 = b'\xa9'
OP_EQUALVERIFY = b'\x88'
OP_CHECKSIG = b'\xac'

SIGHASH_ALL = b'\x01'


def var_int(num: int) -> bytes:
    if num <= 0xfc:
        ret = num.to_bytes(length=1, byteorder='little', signed=False)
    elif num <= 0xffff:
        ret = b'\xfd' + num.to_bytes(length=2, byteorder='little', signed=False)
    elif num <= 0xffffffff:
        ret = b'\xfe' + num.to_bytes(length=4, byteorder='little', signed=False)
    else:
        ret = b'\xff' + num.to_bytes(length=8, byteorder='little', signed=False)
    return ret


if __name__ == "__main__":
    print("*" * 120 + "\n* Transaction\n" + "*" * 120)

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
