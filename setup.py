from pathlib import Path

from setuptools import setup

CWD = Path(__file__).resolve().parent

# Install Instrucitions
# $ python setup.py install
# $ pip install -e .

my_package = 'candidateblock_bitcoin_library'

# # Read the package version from version.py file
# # Don't import package to get version as won't work
# globals = {}
# locals = {}
# filename = "src/version.py"
# with open(filename, "rb") as source_file:
#     code = compile(source_file.read(), filename, "exec")
# exec(code, globals, locals)

setup(
    name=my_package,
    # version=locals.get('__version__'),
    version='0.0.0',
    description='A useful module',
    url='http://github.com/canddidateblock/candidateblock_bitcoin_library',
    author='CandidateBlock',
    author_email='candidateblock@canddidateblock.com',
    license='MIT',
    package_dir={"": "src"},
    # packages=find_packages(where="candidateblock_bitcoin_library"),
    # package_dir={"": "candidateblock_bitcoin_library"},
    packages=['candidateblock_bitcoin_library'],  # same as name
    install_requires=[
        "ecdsa"
    ],
    # scripts=['scripts/main'],
)
