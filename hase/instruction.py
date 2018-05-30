class Instruction(object):
    """
    This class is used by the C extension _pt
    """

    def __init__(self, ip, size):
        # type: (int, int) -> None
        self.ip = ip
        self.size = size
