from __future__ import absolute_import, division, print_function

import os
from pathlib import Path


TEST_ROOT = Path(os.path.dirname(os.path.realpath(__file__)))
TEST_BIN = Path(str(TEST_ROOT.joinpath("bin")))
TEST_TRACES = Path(str(TEST_ROOT.joinpath("traces")))
