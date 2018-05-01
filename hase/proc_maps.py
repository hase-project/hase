from __future__ import absolute_import, division, print_function

import os
import json
from collections import OrderedDict

try:
    from typing import Dict, Any, List
except ImportError:
    pass


def parse_permissions(flags):
    # type: (str) -> Dict[str, bool]
    permissions = OrderedDict(
        read=False, write=False, executable=False, shared=False)
    for permission, char in zip(permissions.keys(), flags):
        permissions[permission] = char != "-"
    return permissions


def parse_pid(pid):
    # type: (int) -> List[Dict[str, object]]
    memory_map = []

    with open("/proc/%d/maps" % pid) as map_file:
        for line in map_file:
            columns = line.split()
            if len(columns) == 5:
                addresses, permission, offset, dev, inode = columns
                pathname = None
            else:
                addresses, permission, offset, dev, inode, pathname = columns
                pathname = pathname.replace("\\n", "\n")

            start_address, end_address = addresses.split("-")
            major, minor = dev.split(":")
            entry = dict(
                # keep those strings, since they might overflow in json
                start_address=start_address,
                end_address=end_address,
                permission=parse_permissions(permission),
                offset=offset,
                device=dict(major=major, minor=minor),
                inode=int(inode),
                pathname=pathname)
            memory_map.append(entry)
    return memory_map


if __name__ == "__main__":
    print(json.dumps(parse_pid(os.getpid()), indent=4))
