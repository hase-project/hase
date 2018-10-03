from __future__ import absolute_import, division, print_function

import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.errors import SimProcedureError

from .helper import minmax

class localtime_r(SimProcedure):
    def run(self, timep, result):
        # NOTE: make everything symbolic now
        self._store_amd64(result)
        return result

    def _store_amd64(self, tm_buf):
        store = lambda offset, sym, bits: self.state.memory.store(
            tm_buf + offset,
            self.state.se.Unconstrained(sym, bits, uninitialized=False)
        )

        '''
        struct tm {
            int tm_sec;         /* seconds */
            int tm_min;         /* minutes */
            int tm_hour;        /* hours */
            int tm_mday;        /* day of the month */
            int tm_mon;         /* month */
            int tm_year;        /* year */
            int tm_wday;        /* day of the week */
            int tm_yday;        /* day in the year */
            int tm_isdst;       /* daylight saving time */
        };
        '''

        store(0x00, "tm_sec", 32)
        store(0x04, "tm_min", 32)
        store(0x08, "tm_hour", 32)
        store(0x0c, "tm_mday", 32)
        store(0x10, "tm_mon", 32)
        store(0x14, "tm_year", 32)
        store(0x18, "tm_wday", 32)
        store(0x1c, "tm_yday", 32)
        store(0x20, "tm_isdst", 32)


class localtime(SimProcedure):
    def run(self, timep):
        malloc = SIM_PROCEDURES['libc']['malloc']
        result = self.inline_call(malloc, 0x24).ret_expr
        return self.inline_call(localtime_r, timep, result).ret_expr


class asctime_r(SimProcedure):
    def run(self, tm, buf):
        self.state.memory.store(
            buf,
            self.state.se.Unconstrained(
                'asctime',
                25 * 8
            )
        )
        self.state.memory.store(
            buf + 25 * 8,
            '\x00'
        )
        return buf


class asctime(SimProcedure):
    def run(self, tm):
        malloc = SIM_PROCEDURES['libc']['malloc']
        result = self.inline_call(malloc, 26).ret_expr
        return self.inline_call(asctime_r, tm, result).ret_expr


class ctime_r(SimProcedure):
    def run(self, timep, buf):
        # NOTE: actually mismatched argument
        return self.inline_call(asctime_r, timep, buf).ret_expr


class ctime(SimProcedure):
    def run(self, timep):
        # NOTE: actually mismatched argument
        return self.inline_call(asctime, timep).ret_expr


class gmtime_r(SimProcedure):
    def run(self, timep, result):
        # NOTE: actually mismatched argument
        return self.inline_call(localtime_r, timep, result).ret_expr


class gmtime(SimProcedure):
    def run(self, timep):
        # NOTE: actually mismatched argument
        return self.inline_call(localtime, timep).ret_expr


class mktime(SimProcedure):
    def run(self, tm):
        return self.state.se.Unconstrained("mktime", 64, uninitialized=False)


class strftime(SimProcedure):
    def parse_format(self, fmt_str):
        pass

    def run(self, ptr, maxsize, fmt_str, timeptr):
        if self.state.se.symbolic(fmt_str):
            pass
        if self.state.se.symbolic(maxsize):
            size = self.state.se.eval(maxsize)
        else:
            size = minmax(self, maxsize, self.state.libc.max_str_len)
        self.state.memory.store(ptr, self.state.se.Unconstrained('strftime', size * 8, uninitialized=False))
        return self.state.se.Unconstrained('strtime', 32, uninitialized=False)
