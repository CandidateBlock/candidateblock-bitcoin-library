from setuptools import setup

# Install Instrucitions
# $ python setup.py install
# $ pip install -e .

my_package = 'candidateblock_bitcoin_library'

# Read the package version from version.py file
# Don't import package to get version as won't work 
globals = {}
locals = {}
filename = my_package + "/version.py"
with open(filename, "rb") as source_file:
    code = compile(source_file.read(), filename, "exec")
exec(code, globals, locals)

setup(
    name=my_package,
    version=locals.get('__version__'),
    description='A useful module',
    url='http://github.com/canddidateblock/candidateblock_bitcoin_library',
    author='CandidateBlock',
    author_email='candidateblock@canddidateblock.com',
    license='MIT',
    # packages=find_packages(where="candidateblock_bitcoin_library"),
    # package_dir={"": "candidateblock_bitcoin_library"},
    packages=[my_package],  # same as name
    install_requires=[
        "ecdsa"
    ],
    # scripts=['scripts/main'],
)
