import hashlib
from typing import List, Union

import ecdsa

import candidateblock_bitcoin_library as cbl

OP_DUP = 118
OP_HASH160 = 169
OP_EQUALVERIFY = 136
OP_CHECKSIG = 172


def encode_int(i, nbytes, encoding='little'):
    """ encode integer i into nbytes bytes using a given byte ordering """
    return i.to_bytes(nbytes, encoding)


def encode_varint(i):
    """ encode a (possibly but rarely large) integer into bytes with a super simple compression scheme """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("integer too large: %d" % (i, ))


class Script:
    def __init__(self, cmds: List[Union[int, bytes]]):
        self.cmds = cmds

    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            elif isinstance(cmd, bytes):
                # bytes represent an element, encode its length and then content
                length = len(cmd)
                assert length < 75  # any longer than this requires a bit of tedious handling that we'll skip here
                out += [encode_int(length, 1), cmd]

        ret = b''.join(out)
        return encode_varint(len(ret)) + ret


class TxIn:
    def __init__(self, prev_tx: bytes, prev_index: int, script_sig: Script = None, sequence: int = 0xffffffff):
        self.prev_tx = prev_tx  # prev transaction ID: hash256 of prev tx contents
        self.prev_index = prev_index  # UTXO output index in the transaction
        self.script_sig = script_sig  # unlocking script, Script class coming a bit later below
        # originally intended for "high frequency trades", with locktime
        self.sequence = sequence


class TxOut:
    def __init__(self, amount: int, script_pubkey: Script = None):
        self.amount = amount  # in units of satoshi (1e-8 of a bitcoin)
        self.script_pubkey = script_pubkey  # locking script


class Tx:
    def __init__(self, version: int, tx_ins: List[TxIn], tx_outs: List[TxOut], locktime: int = 0):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime

    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]
        # encode outputs
        out += [encode_varint(len(self.tx_outs))]
        out += [tx_out.encode() for tx_out in self.tx_outs]
        # encode... other metadata
        out += [encode_int(self.locktime, 4)]
        out += [encode_int(1, 4) if sig_index != -1 else b'']  # 1 = SIGHASH_ALL
        return b''.join(out)

# we also need to know how to encode TxIn. This is just serialization protocol.


def txin_encode(self, script_override=None):
    out = []
    out += [self.prev_tx[::-1]]  # little endian vs big endian encodings... sigh
    out += [encode_int(self.prev_index, 4)]

    if script_override is None:
        # None = just use the actual script
        out += [self.script_sig.encode()]
    elif script_override is True:
        # True = override the script with the script_pubkey of the associated input
        out += [self.prev_tx_script_pubkey.encode()]
    elif script_override is False:
        # False = override with an empty script
        out += [Script([]).encode()]
    else:
        raise ValueError("script_override must be one of None|True|False")

    out += [encode_int(self.sequence, 4)]
    return b''.join(out)


TxIn.encode = txin_encode  # monkey patch into the class

# and TxOut as well


def txout_encode(self):
    out = []
    out += [encode_int(self.amount, 8)]
    out += [self.script_pubkey.encode()]
    return b''.join(out)


TxOut.encode = txout_encode  # monkey patch into the class

if __name__ == "__main__":

    # pub_key = "mnQVR3Y3z28hDSwYGmbkmUG8WbVLriqrc7"
    # data = cbl.Base58.check_decode(b58=pub_key)
    # address_prefix, payload, checksum = data

    # private_key = bytes.fromhex(
    #     "4f96c5a6f152b7b9194430776fb543d1f23d3fb728e39cc03139725317bea82f")
    # public_key = cbl.Keys.generate_pub_key(priv_key=private_key, is_compressed=True)

    # sk = ecdsa.SigningKey.from_string(string=private_key, curve=ecdsa.SECP256k1)
    # public_key_uncompressed = cbl.Keys.generate_pub_key(
    #     priv_key=private_key, is_compressed=False)
    # vk = sk.verifying_key
    # assert (b'\04' + vk.to_string()) == public_key_uncompressed

    # Key 1
    print("*" * 120 + "\n* Key 1\n" + "*" * 120)
    secret_key1_int = 22265090479312778178772228083027296664144
    secret_key1 = secret_key1_int.to_bytes(length=32, byteorder='big', signed=False)
    print(f"secret key 1 [int] {secret_key1_int}")
    print(f"secret key 1 [hex] {hex(secret_key1_int)}")
    print(f"secret key 1 [Bytes.hex] {secret_key1.hex()}")

    public_key1 = cbl.Keys.generate_pub_key(priv_key=secret_key1, is_compressed=False)
    print(f"public key 1 [Bytes.hex]] {public_key1.hex()}")
    print(
        f"public key 1 [x, y]] {int.from_bytes(public_key1[1:33], byteorder='big')}, {int.from_bytes(public_key1[33:], byteorder='big')}")
    public_key1 = cbl.Keys.generate_pub_key(priv_key=secret_key1, is_compressed=True)
    public_key1_hash160 = cbl.BtcHash.hash160(value=public_key1)
    print(
        f"public key 1 [hash160] {public_key1_hash160.hex()}")
    print(
        f"public key 1 [Base58Check] {cbl.Keys.btc_address_p2pkh(pub_key=public_key1, is_mainnet=False)}")

    # Key 2
    print("*" * 120 + "\n* Key 2\n" + "*" * 120)
    secret_key2_int = int.from_bytes(b"Andrej's Super Secret 2nd Wallet", 'big')
    secret_key2 = secret_key2_int.to_bytes(length=32, byteorder='big', signed=False)
    print(f"secret key 2 [int] {secret_key2_int}")
    print(f"secret key 2 [hex] {hex(secret_key2_int)}")
    print(f"secret key 2 [Bytes.hex] {secret_key2.hex()}")

    public_key2 = cbl.Keys.generate_pub_key(priv_key=secret_key2, is_compressed=False)
    print(f"public key 2 [Bytes.hex]] {public_key2.hex()}")
    print(
        f"public key 2 [x, y]] {int.from_bytes(public_key2[1:33], byteorder='big')}, {int.from_bytes(public_key2[33:], byteorder='big')}")
    public_key2 = cbl.Keys.generate_pub_key(priv_key=secret_key2, is_compressed=True)
    public_key2_hash160 = cbl.BtcHash.hash160(value=public_key2)
    print(
        f"public key 2 [hash160] {public_key2_hash160.hex()}")
    print(
        f"public key 2 [Base58Check] {cbl.Keys.btc_address_p2pkh(pub_key=public_key2, is_mainnet=False)}")

    # Make a transaction
    tx_in = TxIn(
        prev_tx=bytes.fromhex(
            '46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2'),
        prev_index=1,
        script_sig=None,  # this field will have the digital signature, to be inserted later
    )

    tx_out1 = TxOut(
        amount=50000  # we will send this 50,000 sat to our target wallet
    )
    tx_out2 = TxOut(
        amount=47500  # back to us
    )
    # the fee of 2500 does not need to be manually specified, the miner will claim it

    # the first output will go to our 2nd wallet
    out1_pkb_hash = public_key2_hash160
    # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
    out1_script = Script([OP_DUP, OP_HASH160, out1_pkb_hash,
                         OP_EQUALVERIFY, OP_CHECKSIG])
    print(out1_script.encode().hex())
    assert out1_script.encode() == bytes.fromhex(
        "1976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac")

    # the second output will go back to us
    out2_pkb_hash = public_key1_hash160
    out2_script = Script([OP_DUP, OP_HASH160, out2_pkb_hash,
                         OP_EQUALVERIFY, OP_CHECKSIG])
    print(out2_script.encode().hex())
    assert out2_script.encode() == bytes.fromhex(
        "1976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac")

    tx_out1.script_pubkey = out1_script
    tx_out2.script_pubkey = out2_script

    tx = Tx(
        version=1,
        tx_ins=[tx_in],
        tx_outs=[tx_out1, tx_out2],
    )

    # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
    source_script = Script([118, 169, out2_pkb_hash, 136, 172])
    print("recall out2_pkb_hash is just raw bytes of the hash of public_key: ",
          out2_pkb_hash.hex())
    print(source_script.encode().hex())  # we can get the bytes of the script_pubkey now

    # monkey patch this into the input of the transaction we are trying sign and construct
    tx_in.prev_tx_script_pubkey = source_script

    # get the "message" we need to digitally sign!!
    message = tx.encode(sig_index=0)
    print(message.hex())

    correct_message = bytes.fromhex(
        "0100000001b2364d6ba4cbfd3dad8d6dc8dde1095f959bac4ee4ee7c4b8ab99fc885503246010000001976a9144b3518229b0d3554fe7cd3796ade632aff3069d888acffffffff0250c30000000000001976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac8cb90000000000001976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac0000000001000000")
    assert message == correct_message

    # Now we can sign with our private key (owned from last transaction)
    sk = ecdsa.SigningKey.from_string(string=secret_key1, curve=ecdsa.SECP256k1)
    public_key_uncompressed = cbl.Keys.generate_pub_key(
        priv_key=secret_key1, is_compressed=False)
    vk = sk.verifying_key
    assert (b'\04' + vk.to_string()) == public_key_uncompressed
    signature = sk.sign_digest(digest=message, sigencode=ecdsa.util.sigencode_der)
    # signature = sk.sign_digest(digest=message, sigencode=ecdsa.util.sigencode_der_canonize)
    # signature = sk.sign_digest_deterministic(
    #     digest=message, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)

    print(f"signature :{signature.hex()}")
