import os
from hase.path import Path

TEST_ROOT = Path(os.path.dirname(os.path.realpath(__file__)))
TEST_ROOT.bin = Path(TEST_ROOT.join("bin"))
