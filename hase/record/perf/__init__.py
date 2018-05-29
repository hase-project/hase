import os

from .snapshot import PtSnapshot, Cpu, perf_aux_event, itrace_start_event

from typing import IO


class PerfRecord(object):
    def __init__(self):
        # type: () -> None
        self.snapshot = PtSnapshot()  # type: PtSnapshot

    def __enter__(self):
        # type: () -> PerfRecord
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def write(self, directory):
        # type: (str) -> None
        self.snapshot.stop()

        for cpu in self.snapshot.cpus:
            event_path = os.path.join(directory, "cpu-%d.perf-events" % cpu.idx)
            with open(event_path, "wb") as event_file:
                for ev in cpu.events():
                    event_file.write(ev)
                    e = perf_aux_event.from_buffer(ev)
                    print(e.type)
            trace_path = os.path.join(directory, "cpu-%d.trace" % cpu.idx)
            with open(trace_path, "wb") as trace_file:
                for trace in cpu.traces():
                    event = perf_aux_event.from_buffer(trace)
                    if event.type == 11:
                        print("cpu: %d aux_size %x aux_offset %x" % (cpu.idx, event.aux_size, event.aux_offset))
                    trace_file.write(trace)

        conversion = self.snapshot.tsc_conversion()

    def close(self):
        # type: () -> None
        self.snapshot.close()
