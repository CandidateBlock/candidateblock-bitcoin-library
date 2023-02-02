# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""Bitcoin Wallets
The word “wallet” refers to the data structure used to store and
manage a users keys. In a sense the "wallet" is just a keychain.
We will only implement industry-standard-based hierarchical
deterministic (HD BIP-32/BIP-44) wallet with a
mnemonic seed (BIP-39) for backup.
"""

from .base58 import Base58
from .btc_hash import BtcHash
from .keys import Keys
from .prefix import Prefix

# https://iancoleman.io/bip39/
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki Hierarchical Deterministic Wallets
# https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki Multi-Account Hierarchy for Deterministic Wallets


class HdWallet(object):
    """Hierarchical Deterministic Wallet Class

    The word “wallet” refers to the data structure used to store and
    manage a users keys. In a sense the "wallet" is just a keychain.
    We will only implement industry-standard-based hierarchical
    deterministic (HD BIP-32/BIP-44) wallet with a
    mnemonic seed (BIP-39) for backup.
    """

    @ staticmethod
    def master_key_generation(seed: bytes = b''):
        seed_hmac_sha512 = BtcHash.hmac_sha512(key=b"Bitcoin seed", msg=seed)
        master_priv_key = seed_hmac_sha512[:32]    # Left 256-bits
        master_chain_code = seed_hmac_sha512[32:]  # Right 256-bits
        return (master_priv_key, master_chain_code)

    @staticmethod
    def encode(key: bytes = b'', chain_code: bytes = b'', parent_key: bytes = b'', depth: int = 0, child: int = 0,
               is_master: bool = False, is_private: bool = True, is_mainnet: bool = True) -> str:
        """encode
        Extended public and private keys are serialized as follows:

        4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
        1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
        4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
        32 bytes: the chain code
        33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        This 78 byte structure can be encoded like other Bitcoin data in
        Base58, by first adding 32 checksum bits (derived from the double
        SHA-256 checksum), and then converting to the Base58 representation.
        This results in a Base58-encoded string of up to 112 characters.
        Because of the choice of the version bytes, the Base58 representation
        will start with "xprv" or "xpub" on mainnet, "tprv" or "tpub" on testnet.

        Args:
            key (bytes): Private 256-bits (32-Bytes) or COMPRESSED Private key 264-bits (33-Bytes)
            chain_code (bytes): Private or Public Chain Code 256-bits (32-Bytes)
            parent_key (bytes): Parent Key, Private 256-bits (32-Bytes) or COMPRESSED Private key 264-bits (33-Bytes), or nohting if master node
            depth (int): 0 for master nodes, 1 for level-1 derived keys, ....
            child (int): child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
            is_master (bool): Are we encoding (serializing) the master / root key
            is_private (bool): Are we encoding (serializing) as Public or Private key
            is_mainnet (bool): Are we encoding for Mainnet or Testnet

        Returns:
            str: Base58Check encoded
        """
        if is_private:
            if is_mainnet:
                extended_key = Prefix.BIP_32_EXTENDED_PRIVATE_KEY
            else:
                extended_key = Prefix.TESTNET_BIP_32_EXTENDED_PRIVATE_KEY
        else:
            if is_mainnet:
                extended_key = Prefix.BIP_32_EXTENDED_PUBLIC_KEY
            else:
                extended_key = Prefix.TESTNET_BIP_32_EXTENDED_PUBLIC_KEY
        # Depth 1-byte
        extended_key += int(depth).to_bytes(length=1, byteorder='big', signed=False)
        # parent fingerprint 4-bytes
        if is_master:
            extended_key += int(0).to_bytes(length=4, byteorder='big', signed=False)
        else:
            # Private Key so get Public key fingerprint
            pub_key = Keys.generate_pub_key(priv_key=parent_key, is_compressed=True)
            key_hash160 = BtcHash.hash160(value=pub_key)
            # if is_private:
            #     # Private Key so get Public key fingerprint
            #     pub_key = Keys.generate_pub_key(priv_key=parent_key, is_compressed=True)
            #     key_hash160 = BtcHash.hash160(value=pub_key)
            # else:
            #     # Public Key already, so Public Key fingerprint
            #     key_hash160 = BtcHash.hash160(value=parent_key)
            key_fingerprint = key_hash160[:4]    # first 32-bits 4-bytes
            extended_key += key_fingerprint

        # child number 4-bytes
        extended_key += int(child).to_bytes(length=4, byteorder='big', signed=False)
        extended_key += chain_code
        if is_private:
            extended_key += b"\x00" + key
        else:
            extended_key += key
        b58_check = Base58.check_encode(payload=extended_key)
        return b58_check

    @ staticmethod
    def child_key_derivation(parent_key: bytes,
                             parent_chaincode: bytes,
                             index: int,
                             is_private: bool):
        # Is the child a hardened key
        if index >= 2**31:
            # I = HMAC-SHA512(Key=cpar, Data=0x00 + ser256(kpar) + ser32(i))
            # Note: The 0x00 pads the PRIVATE key to make it 33 bytes long.
            hash_input = b"\x00"
            hash_input += parent_key
            hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
            hmac_sha512 = BtcHash.hmac_sha512(key=parent_chaincode, msg=hash_input)
            child_chaincode = hmac_sha512[32:]  # Right 256-bits
            # PRIVATE child key
            parent_key_int = int.from_bytes(
                bytes=parent_key, byteorder='big', signed=False)
            child_private_key = hmac_sha512[:32]    # Left 256-bits
            child_private_key_int = int.from_bytes(
                bytes=child_private_key, byteorder='big', signed=False)
            n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if child_private_key_int == 0 or child_private_key_int >= n:
                #  resulting key is invalid, and one should proceed with the next value for i.
                #  (Note: this has probability lower than 1 in 2127.)
                # TODO - fix this use next index value to get next key
                pass

            child_private_key_int = int(
                (child_private_key_int + parent_key_int) % n)
            child_private_key = child_private_key_int.to_bytes(
                length=32, byteorder='big', signed=False)
            child_key = child_private_key

        else:
            # I = HMAC-SHA512(Key=cpar, Data=serP(point(kpar)) + ser32(i)).
            pub_key = Keys.generate_pub_key(priv_key=parent_key, is_compressed=True)
            hash_input = pub_key
            hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
            hmac_sha512 = BtcHash.hmac_sha512(key=parent_chaincode, msg=hash_input)
            child_chaincode = hmac_sha512[32:]  # Right 256-bits
            # PUBLIC child key
            parent_key_int = int.from_bytes(
                bytes=parent_key, byteorder='big', signed=False)
            child_public_key = hmac_sha512[:32]    # Left 256-bits
            child_public_key_int = int.from_bytes(
                bytes=child_public_key, byteorder='big', signed=False)
            n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if child_public_key_int == 0 or child_public_key_int >= n:
                #  resulting key is invalid, and one should proceed with the next value for i.
                #  (Note: this has probability lower than 1 in 2127.)
                # TODO - fix this use next index value to get next key
                pass

            child_public_key_int = int(
                (child_public_key_int + parent_key_int) % n)
            child_public_key = child_public_key_int.to_bytes(
                length=32, byteorder='big', signed=False)
            child_key = child_public_key

        return (child_key, child_chaincode)

        # @ staticmethod
        # def child_key_derivation(parent_key: bytes,
        #                          parent_chaincode: bytes,
        #                          depth: int,
        #                          index: int,
        #                          is_private: bool):
        #     """Mnemonic words are generated automatically by the wallet using the
        #     standardized process defined in BIP-39.

        #     Create a random sequence (entropy) of 128 to 256 bits.
        #     Create a checksum of the random sequence by taking the first (entropy-length/32) bits of its SHA256 hash.
        #     Add the checksum to the end of the random sequence.
        #     Split the result into 11-bit length segments.
        #     Map each 11-bit value to a word from the predefined dictionary of 2048 words.
        #     The mnemonic code is the sequence of words.

        #     Args:
        #         words (int): Number of words only valid values 12, 15, 18, 21 or 24

        #     Returns:
        #         str: A string storing Mnemonic 12-24 words
        #     """

        #     # Is this a public or private parent key
        #     if is_private:
        #         parent_priv_key = parent_key
        #         keys = Keys()
        #         keys.private_key = int.from_bytes(
        #             bytes=parent_priv_key, byteorder='big', signed=False)
        #         keys.generate_public_key()
        #         parent_pub_key = bytes.fromhex(keys.get_public_key_compressed_hex())
        #     else:
        #         parent_priv_key = None
        #         parent_pub_key = parent_key

        #     # Is the child a hardened key
        #     if index >= 2**31:
        #         #  = HMAC - SHA512(Key=cpar, Data=0x00 | | ser256(kpar) | | ser32(i)). ()
        #         if not is_private:
        #             raise Exception("Can't do private derivation on public key!")
        #         # Note: The 0x00 pads the PRIVATE key to make it 33 bytes long.
        #         hash_input = b"\x00"
        #         hash_input += parent_priv_key
        #         hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
        #         hmac_sha512 = hmac.new(key=parent_chaincode,
        #                                msg=hash_input,
        #                                digestmod=hashlib.sha512).digest()
        #     else:
        #         # Note: COMPRESSED PUBLIC key is 33 bytes long
        #         hash_input = parent_pub_key
        #         hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
        #         hmac_sha512 = hmac.new(key=parent_chaincode,
        #                                msg=hash_input,
        #                                digestmod=hashlib.sha512).digest()
        #     if is_private:
        #         child_chaincode = hmac_sha512[32:]  # Right 256-bits
        #         # PRIVATE child key
        #         child_private_key = hmac_sha512[:32]    # Left 256-bits
        #         parent_private_key_int = int.from_bytes(
        #             bytes=parent_priv_key, byteorder='big', signed=False)
        #         child_private_key_int = int.from_bytes(
        #             bytes=child_private_key, byteorder='big', signed=False)
        #         n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        #         child_private_key_int = int(
        #             (child_private_key_int + parent_private_key_int) % n)
        #         child_private_key = child_private_key_int.to_bytes(
        #             length=32, byteorder='big', signed=False)
        #         # Get parent PUBLIC key fingerprint
        #         # 256-byte hash = 32-Bytes = 64 Hex Chars
        #         key_sha256 = hashlib.new("sha256", parent_pub_key).digest()
        #         # 160-byte hash (smaller for less data in Bitcoin address) = 20-Bytes = 40 Hex Chars
        #         key_ripemd160 = hashlib.new("ripemd160", key_sha256).digest()
        #         parent_key_fingerprint = key_ripemd160[:4]    # first 32-bits 4-bytes
        #     else:
        #         pass

        #     xprv = int(depth).to_bytes(length=1, byteorder='big', signed=False)
        #     xprv += parent_key_fingerprint
        #     xprv += index.to_bytes(length=4, byteorder='big', signed=False)
        #     xprv += child_chaincode
        #     xprv += b"\x00" + child_private_key
        #     xprv_base58 = Base58.check_encode(
        #         s_hex=xprv.hex(), version_prefix=Prefix.BIP_32_EXTENDED_PRIVATE_KEY)
        #     print(f'xprv_base58: {xprv_base58}')