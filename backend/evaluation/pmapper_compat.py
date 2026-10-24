
"""
Compatibility launcher for PMapper 1.1.5 on Python 3.11.
"""

import collections
import collections.abc
import runpy

collections.Mapping = collections.abc.Mapping
collections.MutableMapping = collections.abc.MutableMapping

if __name__ == "__main__":
    runpy.run_module("principalmapper", run_name="__main__")
