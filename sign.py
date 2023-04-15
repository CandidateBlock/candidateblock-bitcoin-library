import hashlib

import ecdsa

import candidateblock_bitcoin_library as cbl

private_key = bytes.fromhex(
    "4f96c5a6f152b7b9194430776fb543d1f23d3fb728e39cc03139725317bea82f")
trans_sig_ready = bytes.fromhex(
    "020000000166e0f7a46e2b9b5cd06af95750695f24dda315ad1c5c3b4138b75fe828f54f1f010000001976a914bc2f4d0c573fa402b10e88f281e0b8129760597088acffffffff0150260000000000001976a914bc2f4d0c573fa402b10e88f281e0b8129760597088ac0000000001000000")
tx_id = bytes.fromhex(
    "569e326a8cb13bf3f02e9010b17bc3ff8c9b820f3fd6c8a8332af7f99b7189ff")
correct_sig = bytes.fromhex(
    "627cc55e5eb09770c1efe4ae5a7e5da2edc636ae11c79f699332fc1398e70bd0bfc8316e82fd97a49d50d921eff0750aca77c95e57d0e70e46e55175cf8c4b04")
correct_sig_der = bytes.fromhex(
    "304402201903ca8e1c52e861dc57bee84bd67273f25b88270ba95c974dcab651de08a05f02206044d68b732d88446e6c374b38ffe3bb74d2c04ba6919e93b4927b7cde7a26ea")


def nice(name: str, input: bytes) -> None:
    print(f"{name}: ({len(input)}|{len(input)*8}) {input.hex()}")


if __name__ == "__main__":
    print("*" * 150)

    # Set signing key (private key)
    print("-" * 150)
    sk = ecdsa.SigningKey.from_string(
        string=private_key, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    nice(name="sk     ", input=sk.to_string())
    assert sk.to_string() == private_key

    # Get verifying key (public key)
    print("-" * 150)
    vk = sk.verifying_key
    nice(name="vk     ", input=vk.to_string())
    nice(name="vk Comp", input=vk.to_string("compressed"))

    # txid = Double sha256 hash of transcation
    print("-" * 150)
    msg = hashlib.sha256(hashlib.sha256(trans_sig_ready).digest()).digest()
    nice(name="Txid   ", input=msg)
    assert msg == tx_id
    # msg = msg[::-1]   # Little-Endian

    # Sign txid
    msg_single_sha = hashlib.sha256(trans_sig_ready).digest()
    # sig = sk.sign_deterministic(
    #     data=msg_single_sha, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string)
    # nice(name="sig    ", input=sig)
    # sig_dig = sk.sign_digest_deterministic(
    #     digest=msg, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string)
    # nice(name="SigOld1", input=sig_dig)
    sig_der = sk.sign_digest_deterministic(
        digest=msg, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der, extra_entropy=b"")
    nice(name="SigOld1", input=sig_der)
    grind = True
    if grind:
        counter = 1
        while len(sig_der) > 70:
            sig_der = sk.sign_digest_deterministic(
                digest=msg, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der, extra_entropy=counter.to_bytes(32, 'little'))
            nice(name="SigNewX", input=sig_der)
            counter += 1
            # just in case we get in infinite loop for some reason
            if counter > 200:
                break
    nice(name="SigNewF", input=sig_der)
    nice(name="SigCorr", input=correct_sig_der)

    # # Check verifying key confirms message signed correcly
    # assert vk.verify_digest(signature=sig_dig, digest=msg) is True

    print("-" * 150)
    # But does not match correct vlaue
    # assert sig_dig == correct_sig

    sig_der = cbl.py_secp256k1.ecdsa_sign(msg, private_key)
    nice(name="SigNew1", input=sig_der)
    grind = True
    if grind:
        counter = 1
        while len(sig_der) > 70:
            sig_der = cbl.py_secp256k1.ecdsa_sign(
                msg, private_key, None, counter.to_bytes(32, 'little'))
            nice(name="SigNewX", input=sig_der)
            counter += 1
            # just in case we get in infinite loop for some reason
            if counter > 200:
                break
    nice(name="SigNewF", input=sig_der)
    nice(name="SigCorr", input=correct_sig_der)
    assert sig_der == correct_sig_der
