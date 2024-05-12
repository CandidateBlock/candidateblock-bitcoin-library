# Copyright (c) 2023 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""Bitcoin Wallets
The word “wallet” refers to the data structure used to store and
manage a users keys. In a sense the "wallet" is just a keychain.
We will only implement industry-standard-based hierarchical
deterministic (HD BIP-32/BIP-44) wallet with a
mnemonic seed (BIP-39) for backup.
"""
# import re
import typing
from .base58 import Base58
from .hashes import Hashes
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

    HARDEND = 2**31  # 2^31 = 0x80000000

    @staticmethod
    def master_key_generation(seed: bytes = b''):
        seed_hmac_sha512 = Hashes.hmac_sha512(key=b"Bitcoin seed", msg=seed)
        master_priv_key = seed_hmac_sha512[:32]    # Left 256-bits
        master_chain_code = seed_hmac_sha512[32:]  # Right 256-bits
        # Private Key so get Public key fingerprint
        pub_key = Keys.generate_pub_key(priv_key=master_priv_key, is_compressed=True)
        key_hash160 = Hashes.hash160(value=pub_key)
        master_fingerprint = key_hash160[:4]    # first 32-bits 4-bytes
        return (master_priv_key, master_chain_code, master_fingerprint)

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
            key_hash160 = Hashes.hash160(value=pub_key)
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

    @classmethod
    def child_key_derivation(self,
                             parent_key: bytes,
                             parent_chaincode: bytes,
                             index: int,
                             is_private: bool):
        # Is the child a hardened key
        if index >= self.HARDEND:
            # I = HMAC-SHA512(Key=cpar, Data=0x00 + ser256(kpar) + ser32(i))
            # Note: The 0x00 pads the PRIVATE key to make it 33 bytes long.
            hash_input = b"\x00"
            hash_input += parent_key
            hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
            hmac_sha512 = Hashes.hmac_sha512(key=parent_chaincode, msg=hash_input)
            child_chaincode = hmac_sha512[32:]  # Right 256-bits
            # PRIVATE child key
            child_private_key = hmac_sha512[:32]    # Left 256-bits
            if Keys.is_priv_key_valid(priv_key=child_private_key) is False:
                # TODO - fix this use next index value to get next key
                pass

            child_private_key_int = int.from_bytes(
                bytes=child_private_key, byteorder='big', signed=False)
            parent_key_int = int.from_bytes(
                bytes=parent_key, byteorder='big', signed=False)
            child_private_key_int = int(
                (child_private_key_int + parent_key_int) % Keys._n)
            child_private_key = child_private_key_int.to_bytes(
                length=32, byteorder='big', signed=False)
            child_key = child_private_key

        else:
            # I = HMAC-SHA512(Key=cpar, Data=serP(point(kpar)) + ser32(i)).
            pub_key = Keys.generate_pub_key(priv_key=parent_key, is_compressed=True)
            hash_input = pub_key
            hash_input += index.to_bytes(length=4, byteorder='big', signed=False)
            hmac_sha512 = Hashes.hmac_sha512(key=parent_chaincode, msg=hash_input)
            child_chaincode = hmac_sha512[32:]  # Right 256-bits
            # PUBLIC child key
            child_public_key = hmac_sha512[:32]    # Left 256-bits
            if Keys.is_priv_key_valid(priv_key=child_public_key) is False:
                # TODO - fix this use next index value to get next key
                pass

            child_public_key_int = int.from_bytes(
                bytes=child_public_key, byteorder='big', signed=False)
            parent_key_int = int.from_bytes(
                bytes=parent_key, byteorder='big', signed=False)
            child_public_key_int = int(
                (child_public_key_int + parent_key_int) % Keys._n)
            child_public_key = child_public_key_int.to_bytes(
                length=32, byteorder='big', signed=False)
            child_key = child_public_key

        return (child_key, child_chaincode)

    @classmethod
    def parse_path(self, path: str = "") -> typing.List[int]:
        """Parse Path
        BIP-32 HD wallet path parse and clean hardended
        char ' to H and all upper case

        Args:
            path (str): in form m/84'/0'/1' or m/84h/0h/1h

        Returns:
            List[int]: Array of integers with two dimensions 1. depth, 2. index + hardened [0x800000] if applicable
        """
        if path is None or path == "":
            raise ValueError('path argument is empty')

        # Skip leading spaces & other spacing chars
        path = path.strip(" \t\n\v\f\r")

        # # Check if string only contains allowed characters
        # if re.findall("[^0-9]", path):
        #     raise ValueError(
        #         "path string argument should contain only mh/'0-9 characters")

        path = path.upper()
        path = path.replace("\'", "H")
        path_array = path.split("/")
        path_result = []
        for depth, level in enumerate(path_array):
            if depth == 0:
                index = 0
            else:
                hardend = level.split("H")
                if len(hardend) > 1:
                    index = self.HARDEND + int(hardend[0])
                else:
                    index = int(hardend[0])
            path_result.append([depth, index])

        return path_result
