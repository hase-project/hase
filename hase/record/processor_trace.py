from ..path import Path

PT_ROOT = Path("/sys/bus/event_source/devices/intel_pt")


class PtFeatures:
    def __init__(self, supported=False, ip_filtering=False):
        # type: (bool, bool) -> None
        self.supported = supported
        self.ip_filtering = ip_filtering

    @property
    def large_record_buffer(self):
        # on Broadwell it seems to fail allocate perf buffer large then a page.
        # all generations after Broadwell support also ip_filtering
        return self.ip_filtering


def check_features():
    # type: () -> PtFeatures
    if not PT_ROOT.exists():
        return PtFeatures()

    with open(str(PT_ROOT.join("caps", "ip_filtering"))) as f:
        ip_filtering = int(f.read()) != 0
        return PtFeatures(supported=True, ip_filtering=ip_filtering)
