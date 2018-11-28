import subprocess
from typing import Any, Dict, List

from pygdbmi.gdbcontroller import GdbController

from ..path import APP_ROOT
from ..pt.events import Instruction

DEFAULT_RR_PATH = APP_ROOT.joinpath("/bin/rr")


def rr_record(binary_path: str, *args: str) -> None:
    proc = subprocess.Popen([str(DEFAULT_RR_PATH), "replay", binary_path] + list(args))
    proc.wait()
    if proc.stdout:
        lines = proc.stdout.readline().strip()
        print(lines)


class RRController:
    def __init__(self, binary_path: str, trace: List[Instruction]) -> None:
        self.binary_path = binary_path
        self.trace = trace
        self.rr = GdbController(
            gdb_path=DEFAULT_RR_PATH, gdb_args=[binary_path], rr=True
        )
        self.current_index = 0

    def eval_expression(self, expr: str) -> None:
        res = self.rr.write("-data-evaluate-expression %s" % expr, timeout_sec=99999)
        print(res)

    def write_request(
        self, req: str, get_resp: bool = True, **kwargs: Any
    ) -> List[Dict[str, Any]]:
        timeout_sec = kwargs.pop("timeout_sec", 10)
        kwargs["read_response"] = False
        self.rr.write(req, timeout_sec=timeout_sec, **kwargs)
        resp: List[Dict[str, Any]] = []
        if get_resp:
            while True:
                try:
                    resp += self.rr.get_gdb_response()
                except Exception:
                    break
        return resp

    def count_occurence(self, idx: int) -> int:
        """Count # of addr -> target in trace"""
        instruction = self.trace[idx]
        addr = instruction.ip
        cnt = 0
        step = 1 if idx > self.current_index else -1
        for i in range(self.current_index, idx, step):
            e = self.trace[i]
            if e.ip == addr:
                cnt += 1
        return cnt

    def run_until(self, idx: int) -> None:
        instruction = self.trace[idx]
        addr = instruction.ip
        n = self.count_occurence(idx)
        cont_ins = "c" if idx > self.current_index else "reverse-cont"
        self.write_request("b *{}".format(hex(addr)), get_resp=False, timeout_sec=100)
        self.write_request(
            "{} {}".format(cont_ins, n), get_resp=False, timeout_sec=10000
        )
        self.write_request(
            "clear *{}".format(hex(addr)), get_resp=False, timeout_sec=100
        )
