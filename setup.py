# from pathlib import Path

from setuptools import setup

# CWD = Path(__file__).resolve().parent

# Install Instrucitions
# $ python setup.py install
# $ pip install -e .

# Read the package version from version.py file
# Don't import package to get version as won't work
globals = {}
locals = {}
filename = "src/candidateblock_bitcoin_library/version.py"
with open(filename, "rb") as source_file:
    code = compile(source_file.read(), filename, "exec")
exec(code, globals, locals)

setup(
    name='candidateblock_bitcoin_library',
    version=locals.get('__version__'),
    description='candidateblock_bitcoin_library (cbl) is a OO Python package which aims to provide an easy and intuitive way of interacting with the Bitcoin protocol.',
    url='http://github.com/canddidateblock/candidateblock_bitcoin_library',
    author='CandidateBlock',
    author_email='candidateblock@canddidateblock.com',
    license='MIT',
    package_dir={"": "src"},
    packages=['candidateblock_bitcoin_library'],  # same as name
    install_requires=[
        "ecdsa"
    ],
    # scripts=['scripts/main'],
)
