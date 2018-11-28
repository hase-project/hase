import claripy
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES

from .helper import errno_success, minmax, null_success, test_concrete_value
from .sym_struct import passwd

# TODO: getgrgid, getgrnam, getgrent, endgrent, setgrent,
# getgrgid_r, getgrnam_r


class getgrgid(SimProcedure):
    def run(self, gid) -> claripy.BVV:
        malloc = SIM_PROCEDURES["libc"]["malloc"]
        ret_addr = self.inline_call(malloc, 0x18).ret_expr
        self._store_amd64(ret_addr)
        return ret_addr

    def _store_amd64(self, group_buf):
        # store = lambda offset, val: self.state.memory.store(group_buf + offset, val)
        # TODO: complete struct group member
        """
        struct group {
            char* gr_name; // name of the group
            gid_t gr_gid; // group ID, gid_t = 4 bytes
            char** gr_mem; // pointer to a null-terminated array of character
                pointers to member names.
        }
        """
        pass


class getlogin_r(SimProcedure):
    def run(self, name, namesize, size=None) -> claripy.BVV:
        if not size:
            if self.state.solver.symbolic(namesize):
                size = minmax(self, namesize, self.state.libc.max_str_len)
            else:
                size = self.state.solver.eval(namesize)
        self.state.memory.store(
            name,
            self.state.solver.Unconstrained(
                "getlogin_r", size * 8, uninitialized=False
            ),
        )
        return errno_success(self)


class getlogin(SimProcedure):
    def run(self) -> claripy.BVV:
        malloc = SIM_PROCEDURES["libc"]["malloc"]
        addr = self.inline_call(malloc, self.state.libc.max_str_len).ret_expr
        self.inline_call(getlogin_r, addr, self.state.libc.max_str_len)
        return null_success(self, addr)


class getpwuid_r(SimProcedure):
    def run(self, uid, pwd, buffer, bufsize, result) -> claripy.BVV:
        # TODO: add map (uid, passwd) in state, so getpwent may be correct
        pw = passwd(pwd)
        pw.store_all(self)
        malloc = SIM_PROCEDURES["libc"]["malloc"]
        addr = self.inline_call(malloc, self.state.libc.max_str_len).ret_expr
        pw.store(self, "pw_name", addr)
        addr = self.inline_call(malloc, self.state.libc.max_str_len).ret_expr
        pw.store(self, "pw_passwd", addr)
        addr = self.inline_call(malloc, self.state.libc.max_str_len).ret_expr
        pw.store(self, "pw_gecos", addr)
        addr = self.inline_call(malloc, self.state.libc.max_str_len).ret_expr
        pw.store(self, "pw_dir", addr)
        addr = self.inline_call(malloc, self.state.libc.max_str_len).ret_expr
        pw.store(self, "pw_shell", addr)
        if not test_concrete_value(self, buffer, 0):
            if self.state.solver.symbolic(bufsize):
                size = minmax(self, bufsize, self.state.libc.max_str_len)
            else:
                size = self.state.solver.eval(bufsize)
            self.state.memory.store(
                buffer,
                self.state.solver.Unconstrained(
                    "getpwuid_r", size * 8, uninitialized=False
                ),
            )
        if not test_concrete_value(self, result, 0):
            self.state.memory.store(result, pwd)
        return errno_success(self)


class getpwuid(SimProcedure):
    def run(self, uid) -> claripy.BVV:
        malloc = SIM_PROCEDURES["libc"]["malloc"]
        size = passwd.size  # type: ignore
        addr = self.inline_call(malloc, size).ret_expr
        self.inline_call(getpwuid_r, uid, addr, 0, 0, 0)
        return null_success(self, addr)


class getpwnam_r(SimProcedure):
    def run(self, name, pwd, buffer, bufsize, result) -> claripy.BVV:
        return self.inline_call(getpwuid_r, name, pwd, buffer, bufsize, result).ret_expr


class getpwnam(SimProcedure):
    def run(self, name) -> claripy.BVV:
        return self.inline_call(getpwuid, name).ret_expr


class getpwent(SimProcedure):
    def run(self) -> claripy.BVV:
        return self.inline_call(getpwuid, 0).ret_expr
