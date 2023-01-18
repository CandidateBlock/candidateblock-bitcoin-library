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

from .base58 import Base58
from .btc_hash import BtcHash
from .keys import Keys
from .prefix import Prefix
from .version import __version__ as version
from .wallet import Wallet

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

__version__ = version
__all__ = ["Base58", "BtcHash", "Keys", "Prefix", "Wallet"]
