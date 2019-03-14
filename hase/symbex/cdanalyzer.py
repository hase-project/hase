from typing import Any, Dict, List, Optional, Tuple

from pygdbmi.gdbcontroller import GdbController

from ..pwn_wrapper import ELF, Coredump


class CoredumpGDB:
    def __init__(
        self, elf: ELF, coredump: Coredump, lib_text_addrs: Dict[str, int]
    ) -> None:
        self.coredump = coredump
        self.elf = elf
        self.corefile = self.coredump.file.name
        self.execfile = self.elf.file.name
        self.gdb = GdbController(gdb_args=["--quiet", "--interpreter=mi2"])
        self.lib_text_addrs = lib_text_addrs
        self.get_response()
        self.setup_gdb()

    def setup_gdb(self) -> None:
        self.write_request("file {}".format(self.execfile))
        self.write_request("core-file {}".format(self.corefile))
        for path, value in self.lib_text_addrs.items():
            self.write_request("add-symbol-file {} {}".format(path, value))
            self.write_request("y")

    def get_response(self) -> List[Dict[str, Any]]:
        resp = []  # type: List[Dict[str, Any]]
        while True:
            try:
                resp += self.gdb.get_gdb_response()
            except Exception:
                break
        return resp

    def write_request(self, req: str, **kwargs: Any) -> List[Dict[str, Any]]:
        self.gdb.write(req, timeout_sec=1, read_response=False, **kwargs)
        resp = self.get_response()
        return resp

    def parse_frame(self, r: str) -> Dict[str, Any]:
        attrs = {}  # type: Dict[str, Any]
        # NOTE: #n  addr in func (args=args[ <name>][@entry=v]) at source_code[:line]\n
        r = r.replace("\\n", "")
        attrs["index"] = r.partition(" ")[0][1:]
        r = r.partition(" ")[2][1:]
        attrs["addr"] = r.partition(" ")[0]
        r = r.partition(" ")[2]
        r = r.partition(" ")[2]
        attrs["func"] = r.partition(" ")[0]
        r = r.partition(" ")[2]
        args = r.partition(")")[0][1:].split(", ")
        args_list = []

        # NOTE: remove <xxx>
        def remove_comment(arg: str) -> str:
            if arg.find("<") != -1:
                arg = arg.partition("<")[0]
                arg = arg.replace(" ", "")
            return arg

        for arg in args:
            if arg.find("@") != -1:
                name, _, entry_ = arg.partition("@")
            else:
                name = arg
                entry_ = ""
            name, _, value = name.partition("=")
            value = remove_comment(value)
            if entry_:
                _, _, entry = entry_.partition("=")
                entry = remove_comment(entry)
                args_list.append([name, value, entry])
            else:
                args_list.append([name, value, ""])
        attrs["args"] = args_list
        r = r.partition(")")[2]
        r = r.partition(" ")[2]
        r = r.partition(" ")[2]
        if r.find(":") != -1:
            source, _, line = r.partition(":")
        else:
            source = r
            line = "?"
        attrs["file"] = source
        attrs["line"] = line
        return attrs

    def parse_addr(self, r: str) -> int:
        # $n = (...) 0xaddr <name>
        l = r.split(" ")
        for blk in l:
            if blk.startswith("0x"):
                blk = blk.replace("\\t", "").replace("\\n", "")
                return int(blk, 16)
        return 0

    def parse_offset(self, r: str) -> int:
        # addr <+offset>:  inst
        l = r.split(" ")
        for blk in l:
            if blk.startswith("<+"):
                idx = blk.find(">")
                return int(blk[2:idx])
        return 0

    def backtrace(self) -> List[Dict[str, Any]]:
        resp = self.write_request("where")
        bt = []
        for r in resp:
            payload = r["payload"]
            if payload and payload[0] == "#":
                print(payload.replace("\\n", ""))
                bt.append(self.parse_frame(payload))
        return bt

    def get_symbol(self, addr: int) -> str:
        resp = self.write_request("info symbol {}".format(addr))
        return resp[1]["payload"]

    def get_reg(self, reg_name: str) -> int:
        resp = self.write_request("info reg {}".format(reg_name))
        for r in resp:
            if "payload" in r.keys():
                if r["payload"].startswith(reg_name):
                    vs = r["payload"].split(" ")
                    for v in vs:
                        if v.startswith("0x"):
                            v = v.replace("\\n", "").replace("\\t", "")
                            return int(v, 16)
        return 0

    def get_stack_base(self, n: int) -> Tuple[int, int]:
        self.write_request("select-frame {}".format(n))
        rsp_value = self.get_reg("rsp")
        rbp_value = self.get_reg("rbp")
        return rsp_value, rbp_value

    def get_func_range(self, name: str) -> List[int]:
        # FIXME: Not a good idea. Maybe some gdb extension?
        r1 = self.write_request("print &{}".format(name))
        addr = 0
        for r in r1:
            if r.get("payload") is not None:
                payload = r["payload"]
                if isinstance(payload, str) and payload.startswith("$"):
                    addr = self.parse_addr(payload)
                    break
        r2 = self.write_request("disass {}".format(name))
        size = 0
        for r in r2[::-1]:
            if r.get("payload") is not None:
                payload = r["payload"]
                if isinstance(payload, str) and "<+" in payload:
                    size = self.parse_offset(payload)
                    break
        return [addr, size + 1]


class CoredumpAnalyzer:
    def __init__(
        self, elf: ELF, coredump: Coredump, lib_text_addrs: Dict[str, int]
    ) -> None:
        self.coredump = coredump
        self.elf = elf
        self.gdb = CoredumpGDB(elf, coredump, lib_text_addrs)
        self.backtrace = self.gdb.backtrace()
        self.argc = self.coredump.argc
        self.argv = [self.read_argv(i) for i in range(self.argc)]
        self.argv_addr = [self.read_argv_addr(i) for i in range(self.argc)]

    def read_stack(self, addr: int, length: int = 0x1) -> str:
        # NOTE: a op b op c will invoke weird typing
        assert self.coredump.stack.start <= addr < self.coredump.stack.stop
        offset = addr - self.coredump.stack.start
        return self.coredump.stack.data[offset : offset + length]

    def read_argv(self, n: int) -> str:
        assert 0 <= n < self.coredump.argc
        return self.coredump.string(self.coredump.argv[n])

    def read_argv_addr(self, n: int) -> str:
        assert 0 <= n < self.coredump.argc
        return self.coredump.argv[n]

    @property
    def env(self) -> Dict[str, str]:
        return self.coredump.env

    @property
    def registers(self) -> Dict[str, int]:
        return self.coredump.registers

    @property
    def stack_start(self) -> int:
        return self.coredump.stack.start

    @property
    def stack_stop(self) -> int:
        return self.coredump.stack.stop

    def call_argv(self, name: str) -> Optional[List[Optional[int]]]:
        for bt in self.backtrace:
            if bt["func"] == name:
                args = []  # type:  List[Optional[int]]
                for _, value, entry in bt["args"]:
                    if entry:
                        args.append(int(entry, 16))
                    else:
                        if value != "":
                            args.append(int(value, 16))
                        else:
                            args.append(None)
                return args
        return None

    def stack_base(self, name: str) -> Tuple[Optional[int], Optional[int]]:
        for bt in self.backtrace:
            if bt["func"] == name:
                return self.gdb.get_stack_base(int(bt["index"]))
        return (None, None)
