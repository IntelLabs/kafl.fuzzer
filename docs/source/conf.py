# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import sys
from pathlib import Path

DOCS_DIR = Path(__file__).resolve().parent.parent

project = 'kAFL'
copyright = '2022, Steffen Schulz - Mathieu Tarral'
author = 'Steffen Schulz'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    # markdown
    'myst_parser',
    # design
    'sphinx_design',
    # mermaid
    'sphinxcontrib.mermaid',
    # copy on code blocks
    'sphinx_copybutton',
    # autodoc
    'sphinx.ext.autodoc',
    # auto apidoc
    'sphinxcontrib.apidoc',
]
myst_enable_extensions = ["colon_fence"]
myst_heading_anchors = 3

# sphinxcontrib-apidoc
kafl_fuzzer_path = DOCS_DIR.parent / 'kafl_fuzzer'
# update sys.path to find kafl_fuzzer
sys.path.insert(0, str(kafl_fuzzer_path.parent))
apidoc_module_dir = str(kafl_fuzzer_path)
apidoc_output_dir = str(DOCS_DIR / 'source' / 'api')
apidoc_toc_file = False
apidoc_excluded_paths = ['tests']
apidoc_separate_modules = True

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_title = project
html_theme = 'furo'
html_theme_options = {
    # TODO: edit when PR on upstream repo
    "source_repository": "https://github.com/IntelLabs/kAFL",
    "source_branch": "docs",
    "source_directory": "docs/source",
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/IntelLabs/kAFL",
            "html": """
                <svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 16 16">
                    <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path>
                </svg>
            """,
            "class": "",
        },
    ],
}
