# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""
Candidate Block Bitcoin Library (cbl), easy to learn, fast to code
==================================================================

cbl is a Python module aims to provide simple and efficient solutions
to learning and using the Bitcoin protocol.

See https://candidateblock-bitcoin-library.readthedocs.io for complete documentation.
"""
import logging

import candidateblock_bitcoin_library.base58 as base58
import candidateblock_bitcoin_library.hash as hash

from .address_prefix import AddressPrefix
from .keys import Keys
from .wallet import Wallet
from .version import __version__ as version

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

__all__ = ["AddressPrefix", "base58", "hash", "Keys", "Wallet"]

__version__ = version
