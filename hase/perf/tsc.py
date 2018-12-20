class TscConversion:
    def __init__(self, time_mult: int, time_shift: int, time_zero: int) -> None:
        self.time_mult = time_mult
        self.time_shift = time_shift
        self.time_zero = time_zero

    def tsc_to_perf_time(self, tsc: int) -> int:
        quot = (tsc >> self.time_shift) * self.time_mult
        rem = ((tsc & ((1 << self.time_shift) - 1)) * self.time_mult) >> self.time_shift
        return self.time_zero + quot + rem

    def perf_time_to_tsc(self, time: int) -> int:
        time -= self.time_zero
        return ((time // self.time_mult) << self.time_shift) + (
            ((time % self.time_mult) << self.time_shift) // self.time_mult
        )


if __name__ == "__main__":
    t = TscConversion(2, 3, 4)
    assert 50 == t.tsc_to_perf_time(t.perf_time_to_tsc(50))
