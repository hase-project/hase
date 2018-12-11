import logging
import time
from pathlib import Path
from typing import Optional, Union

l = logging.getLogger(__name__)


class EstimatedTimeTooLong(Exception):
    pass


def format_duration(seconds: Union[float, int]) -> str:
    return time.strftime("%H:%M:%S", time.gmtime(seconds))


class ProgressLog:
    def __init__(
        self,
        name: str,
        total_steps: int,
        log_frequency: int = 100,
        kill_limit: Optional[int] = None,
    ) -> None:
        self.name = name
        self.total_steps = total_steps
        self.start_time = time.time()
        self.log_steps = max(total_steps // log_frequency, 1)
        self.kill_limit = kill_limit

    def update(self, done_steps: int) -> None:
        if done_steps == 0 or done_steps % self.log_steps != 0:
            return
        elapsed_seconds = time.time() - self.start_time
        estimated_seconds = (elapsed_seconds / done_steps) * (
            self.total_steps - done_steps
        )
        elapsed_time = format_duration(elapsed_seconds)
        estimated_time = format_duration(estimated_seconds)
        percent = (done_steps / self.total_steps) * 100

        if self.kill_limit is not None and estimated_seconds > self.kill_limit:
            l.warning(
                "{}: would take too long! ({} > {}), {:.0f}% elapsed: {} instr./s: {}, processed instr: {}, total instr.: {}".format(
                    self.name,
                    estimated_time,
                    format_duration(self.kill_limit),
                    percent,
                    elapsed_time,
                    done_steps / elapsed_seconds,
                    done_steps,
                    self.total_steps,
                )
            )
            raise EstimatedTimeTooLong(
                f"{self.name} would take too long: {estimated_time}"
            )

        l.warning(
            "{}: {:.0f}% elapsed: {}, estimated: {}, instr./s: {}, processed instr: {}, total instr.: {}".format(
                self.name,
                percent,
                elapsed_time,
                estimated_time,
                done_steps / elapsed_seconds,
                done_steps,
                self.total_steps,
            )
        )
