from __future__ import absolute_import, division, print_function

from numpy import uint64

ONE = uint64(1)

class TscConverter(object):
    def __init__(self, time_zero, time_shift, time_mult):
        # type: (int, int, int) -> None
        self.time_zero = uint64(time_zero)
        self.time_shift = uint64(time_shift)
        self.time_mult = uint64(time_mult)

        assert self.time_mult != 0

    def perf_time_to_tsc(self, time):
        # type: (int) -> int
        time = uint64(time) - self.time_zero
        tsc = ((time // self.time_mult) << self.time_shift) \
                + (((time % self.time_mult) << self.time_shift) // self.time_mult)
        return int(tsc)

    def tsc_to_perf_time(self, tsc):
        # type: (int) -> int
        tsc = uint64(tsc)
        quot = (tsc >> self.time_shift) * self.time_mult;
        rem = ((tsc & ((ONE << self.time_shift) - ONE)) * self.time_mult) >> self.time_shift;
        return int(self.time_zero + quot + rem)
