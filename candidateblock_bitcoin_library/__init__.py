# Copyright (c) 2022 CandidateBlock
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

"""
Candidate Block Bitcoin framework, easy to learn, fast to code
==============================================================

sklearn is a Python module integrating classical machine
learning algorithms in the tightly-knit world of scientific Python
packages (numpy, scipy, matplotlib).

It aims to provide simple and efficient solutions to learning problems
that are accessible to everybody and reusable in various contexts:
machine-learning as a versatile tool for science and engineering.

See http://scikit-learn.org for complete documentation.
"""
import logging

import candidateblock_bitcoin_library.base58 as base58
import candidateblock_bitcoin_library.hash as hash

from .address_prefix import AddressPrefix
from .keys import Keys
from .version import __version__ as version

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

__all__ = ["AddressPrefix", "base58", "hash", "Keys"]

__version__ = version
