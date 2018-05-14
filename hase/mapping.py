from __future__ import absolute_import, division, print_function
from typing import NamedTuple

Mapping = NamedTuple("Mapping", [("path", str), ("start", int), ("stop", int),
                                 ("flags", str)])
