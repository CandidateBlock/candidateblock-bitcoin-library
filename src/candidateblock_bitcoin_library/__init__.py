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

from .address_prefix import AddressPrefix
from .base58 import Base58
from .hash import Hash
from .keys import Keys
from .version import __version__ as version
from .wallet import Wallet

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

__all__ = ["AddressPrefix", "Base58", "Hash", "Keys", "Wallet"]
__version__ = version
