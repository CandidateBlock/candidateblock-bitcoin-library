
import candidateblock_bitcoin_library as cbl


def sign(msg_hash, secret, grind=True):
    sig = cbl.py_secp256k1.ecdsa_sign(msg_hash, secret)
    if grind:
        counter = 1
        while len(sig) > 70:
            sig = cbl.py_secp256k1.ecdsa_sign(
                msg_hash, secret, None, counter.to_bytes(32, 'little'))
            counter += 1
            # just in case we get in infinite loop for some reason
            if counter > 200:
                break
    return sig


h = bytes.fromhex("b346fb71c824b732b400e4d028dccb4f32f99b159d044a8ac1f8cc9de0cc8dd2")
secret = bytes.fromhex(
    "4f96c5a6f152b7b9194430776fb543d1f23d3fb728e39cc03139725317bea82f")

sig = sign(msg_hash=h, secret=secret, grind=True)
print(sig.hex())
