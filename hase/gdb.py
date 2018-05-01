from __future__ import absolute_import, division, print_function

import pty
import os
import logging
import tty
import threading
import resource
import termios
import struct
from pygdbmi.gdbcontroller import GdbController

from . import tracer

try:
    from typing import Tuple, IO, Any
except ImportError:
    pass

logging.basicConfig()
l = logging.getLogger(__name__)


def create_pty():
    # type: () -> Tuple[IO[Any], str]
    master_fd, slave_fd = pty.openpty()
    # disable echoing
    tty.setraw(master_fd, termios.TCSANOW)
    tty.setraw(slave_fd, termios.TCSANOW)
    ptsname = os.ttyname(slave_fd)
    os.close(slave_fd)
    # make i/o unbuffered
    return os.fdopen(master_fd, "rw+", 0), ptsname


PAGESIZE = resource.getpagesize()


def compute_checksum(data):
    # type: (str) -> int
    return sum((ord(c) for c in data)) % 256


class GdbServer():
    def __init__(self, active_state, binary):
        # type: (tracer.State, str) -> None
        master, ptsname = create_pty()
        self.master = master
        self.COMMANDS = {
            'q': self.handle_query,
            'g': self.read_register,
            'm': self.read_memory,
            'H': self.set_thread,
            'v': self.handle_long_commands,
            '?': self.stop_reason,
        }
        self.active_state = active_state
        self.gdb = GdbController()
        self.gdb.write("-target-select remote %s" % ptsname)
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

        self.gdb.write("-file-exec-and-symbols %s" % binary)

    def eval_expression(self, expr):
        # type: (str) -> None
        res = self.gdb.write("-data-evaluate-expression %s" % expr, timeout_sec=99999)
        print(res)

    def run(self):
        # () -> None
        l.info("start server gdb server")
        buf = []
        while True:
            try:
                data = os.read(self.master.fileno(), PAGESIZE)
            except OSError as e:
                l.info("gdb connection was closed: %s", e)
                return

            if len(data) == 0:
                l.debug("gdb connection was closed")
            buf += data
            buf = self.process_data(buf)

    @property
    def active_state(self):
        # type: () -> tracer.State
        return self.state

    @active_state.setter
    def active_state(self, state):
        # type: (tracer.State) -> None
        self.state = state

    def process_data(self, buf):
        # type: (str) -> str
        while len(buf):
            if buf[0] == "+" or buf[0] == "-":
                buf = buf[1:]
                if len(buf) == 0:
                    return buf

            begin = buf.index("$") + 1
            end = buf.index("#")
            if begin >= 0 and end < len(buf):
                packet = buf[begin:end]
                checksum = int(buf[end + 2], 16)
                checksum += int(buf[end + 1], 16) << 4
                assert checksum == compute_checksum(packet)

                self.process_packet(packet)
                buf = buf[end + 3:]
        return buf

    def write_ack(self):
        # type: () -> None
        self.master.write("+")
        self.master.flush()

    def process_packet(self, packet):
        # type: (str) -> None
        handler = self.COMMANDS.get(packet[0], None)

        request = "".join(packet[1:])
        l.warning("<-- %s%s" % (packet[0], request))

        if handler is None:
            l.warning("unknown command %s%s received" % (packet[0], request))
            response = ""
        else:
            response = handler(request)

        # Each packet should be acknowledged with a single character.
        # '+' to indicate satisfactory receipt
        l.warning("--> %s" % response)
        self.master.write("+$%s#%.2x" % (response, compute_checksum(response)))
        self.master.flush()

    def read_register(self, packet):
        # type: (str) -> str
        """
        g
        """

        # https://github.com/radare/radare2/blob/fe6372339da335bd08a8b568d95bb0bd29f24406/shlr/gdb/src/arch.c#L5
        regs = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
            "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "cs",
            "ss", "ds", "es", "fs", "gs"
        ]

        # return struct.pack('<I' * len(regs), 'xx' * len(regs))
        # return 'xx' * len(regs)
        values = ""
        for name in regs:
            if name in ["cs", "ss", "ds", "es"]:
                values += "xx"
            else:
                reg = self.active_state.registers[name]
                if reg.size == 32:
                    fmt = "<I"
                elif reg.size == 64:
                    fmt = "<Q"
                else:
                    raise Exception("Unsupported bit width %d" % reg.size)
                values += struct.pack(fmt, reg.value).encode("hex")
        return "".join(values)

    def set_thread(self, packet):
        # type: (str) -> str
        return 'OK'

    def read_memory(self, packet):
        # type: (str) -> str
        """
        m addr,length
        """
        idx = packet.index(",")
        addr = int(packet[:idx], 16)
        length = int(packet[idx + 1:], 16)

        mem = self.active_state.memory

        bytes = ""
        for offset in range(length):
            value = mem[addr + offset * 8]
            if value is None:
                bytes += "xx"
            else:
                bytes += "%.2x" % value

        return bytes

    def stop_reason(self, packet):
        # type: (str) -> str
        GDB_SIGNAL_TRAP = 5
        return "S%.2x" % GDB_SIGNAL_TRAP

    def handle_long_commands(self, packet):
        # type: (str) -> str
        if packet.startswith('MustReplyEmpty'):
            return ""
        else:
            l.warning("unknown command: v%s", packet)
            return ""

    def handle_query(self, packet):
        # type: (str) -> str
        """
        qSupported|qAttached|qC
        """

        if packet.startswith('Supported'):
            return 'PacketSize=%x' % PAGESIZE
        elif packet.startswith('Attached'):
            return '1'
        elif packet.startswith("C"):
            # FIXME real thread id
            return ""  # empty means no threads
        elif packet.startswith("fThreadInfo"):
            return "m0"
        elif packet.startswith("sThreadInfo"):
            return "l"
        elif packet.startswith("TStatus"):
            # catch all for all commands we know and don't want to implement
            return ""
        else:
            l.warning("unknown query: %s", packet)
            return ""
