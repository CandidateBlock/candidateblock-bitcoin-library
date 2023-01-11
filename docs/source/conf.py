# if we want Sphinx to autogenerate documentation from the comments of
# our code using the autodoc extension, we have to point Sphinx to the
# directory in which our Python source codes reside.
# import os
# import sys
# sys.path.insert(0, os.path.abspath('../src/candidateblock_bitcoin_library/'))

# *******************
# * First time
# *******************
# $ sphinx-apidoc -f -o docs/source candidateblock_bitcoin_library
# $ sphinx-build -b html docs/source/ docs/build/html
# *******************
# * Rebuild
# *******************
# $ cd docs
# $ make clean
# $ sphinx-apidoc --force --separate  -o ./source ../src/candidateblock_bitcoin_library
# $ make html

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

from candidateblock_bitcoin_library import __version__

project = 'CandidateBlock Bitcoin Library'
copyright = '2023, CandidateBlock@CandidateBlock.com'
author = 'CandidateBlock@CandidateBlock.com'
version = __version__
release = version

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# html_theme = 'alabaster'
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Add any Sphinx extension module names here, as strings
extensions = ['sphinx.ext.napoleon']

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True
