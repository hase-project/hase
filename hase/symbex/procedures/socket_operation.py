from __future__ import absolute_import, division, print_function

import claripy
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES


class __recv_chk(SimProcedure):
    def run(self, fd, buf, len, buflen, flag) -> claripy.BVV:
        recv = SIM_PROCEDURES["libc"]["recv"]
        return self.inline_call(recv, fd, buf, len, flag).ret_expr


class __recvfrom_chk(SimProcedure):
    def run(self, fd, buf, len, buflen, flag, from_addr, from_len) -> claripy.BVV:
        recvfrom = SIM_PROCEDURES["libc"]["recvfrom"]
        return self.inline_call(
            recvfrom, fd, buf, len, flag, from_addr, from_len
        ).ret_expr
