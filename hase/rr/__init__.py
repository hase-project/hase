from __future__ import absolute_import, division, print_function

import subprocess
from typing import Any, List, Dict
from pygdbmi.gdbcontroller import GdbController
from ..path import APP_ROOT
from ..pt.events import Instruction

DEFAULT_RR_PATH = APP_ROOT.join('/bin/rr')

def rr_record(binary_path, *args):
    # type: (str, *str) -> None
    proc = subprocess.Popen(
        [
            str(DEFAULT_RR_PATH),
            'replay',
            binary_path,
        ] + list(args),
    )
    proc.wait()
    if proc.stdout:
        lines = proc.stdout.readline().strip()
        print(lines)


class RRController(object):
    def __init__(self, binary_path, trace):
        # type: (str, List[Instruction]) -> None
        self.binary_path = binary_path
        self.trace = trace
        self.rr = GdbController(
            gdb_path=DEFAULT_RR_PATH,
            gdb_args=[binary_path],
            rr=True,
        )
        self.current_index = 0

    def eval_expression(self, expr):
        # type: (str) -> None
        res = self.rr.write(
            "-data-evaluate-expression %s" % expr, timeout_sec=99999)
        print(res)

    def write_request(self, req, get_resp=True, **kwargs):
        # type: (str, bool, *Any) -> List[Dict[str, Any]]
        timeout_sec = kwargs.pop('timeout_sec', 10)
        kwargs['read_response'] = False
        self.rr.write(req, timeout_sec=timeout_sec, **kwargs)
        resp = [] # List
        if get_resp:
            while True:
                try:
                    resp += self.rr.get_gdb_response()
                except:
                    break
        return resp

    def count_occurence(self, idx):
        # type: (int) -> None
        """Count # of addr -> target in trace"""
        event = self.trace[idx]
        addr = event.addr
        cnt = 0
        step = 1 if idx > self.current_index else -1
        for i in range(self.current_index, idx, step):
            e = self.trace[i]
            if e.addr == addr:
                cnt += 1

    def run_until(self, idx):
        # type: (int) -> None
        event = self.trace[idx]
        addr = event.addr
        n = self.count_occurence(idx)
        cont_ins = 'c' if idx > self.current_index else 'reverse-cont'
        self.write_request('b *{}'.format(hex(addr)), get_resp=False, timeout_sec=100)
        self.write_request('{} {}'.format(cont_ins, n), get_resp=False, timeout_sec=10000)
        self.write_request('clear *{}'.format(hex(addr)), get_resp=False, timeout_sec=100)
