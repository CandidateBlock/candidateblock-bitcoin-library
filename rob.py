import candidateblock_bitcoin_library as cbl


priv_key = bytes.fromhex(
    '4f96c5a6f152b7b9194430776fb543d1f23d3fb728e39cc03139725317bea82f')
prv = cbl.py_secp256k1._key.ECKey()
prv.set(secret=priv_key, compressed=True)
assert prv.is_valid
assert prv.get_bytes() == priv_key
print(prv.get_bytes().hex())

pub = prv.get_pubkey()
print(pub.get_bytes().hex())

