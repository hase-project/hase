import pandas as pd
from collections import defaultdict
from .decode import Chunk, ScheduleEntry
from .events import Instruction, TraceEvent
from typing import DefaultDict, List, Any, Union


def to_file(data, filename):
    # type: (DefaultDict[str, List[Any]], str) -> pd.DataFrame
    df = pd.DataFrame(data, dtype=int)
    df.to_csv(filename, sep="\t")
    return df


def traces_to_file(traces, filename):
    # type: (List[List[Union[TraceEvent, Instruction]]], str) -> pd.DataFrame
    df = trace_to_dataframe(traces)
    df.to_csv(filename, sep="\t")
    return df


def instructions_to_file(instructions, filename):
    # type: (List[Instruction], str) -> pd.DataFrame
    data = defaultdict(list)  # type: DefaultDict[str, List[Any]]

    for instruction in instructions:
        data["core"].append(instruction.core)
        data["chunk"].append(instruction.chunk)
        data["ip"].append(instruction.ip)
    return to_file(data, filename)


def chunks_to_file(traces, filename):
    # type: (List[List[Chunk]], str) -> pd.DataFrame
    data = defaultdict(list)  # type: DefaultDict[str, List[Any]]

    for (i, chunks) in enumerate(traces):
        for chunk in chunks:
            for instruction in chunk.instructions:
                data["core"].append(i)
                data["start"].append(chunk.start)
                data["stop"].append(chunk.stop)
                data["ip"].append(chunk.instructions[0].ip)
                data["last_ip"].append(chunk.instructions[-1].ip)
    return to_file(data, filename)


def schedule_to_file(schedule, filename):
    # type: (List[ScheduleEntry], str) -> pd.DataFrame
    data = defaultdict(list)  # type: DefaultDict[str, List[Any]]

    for entry in schedule:
        data["core"].append(entry.core)
        data["pid"].append(entry.pid)
        data["tid"].append(entry.tid)
        data["start"].append(entry.start)
        if entry.stop is None:
            data["stop"].append(0)
        else:
            data["stop"].append(entry.stop)

    return to_file(data, filename)


def trace_to_dataframe(traces):
    # type: (List[List[Union[TraceEvent, Instruction]]]) -> Any
    data = defaultdict(list)  # type: DefaultDict[str, List[Any]]

    for (i, trace) in enumerate(traces):
        time = None
        for ev in trace:
            data["core"].append(i)
            data["type"].append(ev.__class__.__name__)
            if isinstance(ev, Instruction):
                data["ip"].append(ev.ip)
                data["size"].append(ev.size)
                data["time"].append(time)
            else:
                data["ip"].append(None)
                data["size"].append(None)
                time = ev.time
                data["time"].append(time)

    return pd.DataFrame(data, dtype=int)
