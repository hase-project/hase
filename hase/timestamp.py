from datetime import datetime

FORMAT = "%Y%m%dT%H%M%S"


def now() -> str:
    return from_datetime(datetime.utcnow().replace(microsecond=0))


def from_unix_time(time: int) -> str:
    return from_datetime(datetime.utcfromtimestamp(time))


def from_datetime(time: datetime) -> str:
    return time.strftime(FORMAT)


def to_datetime(s: str) -> datetime:
    return datetime.strptime(s, FORMAT)
