# Need to resymbolize hooks
'''
getpid/getppid/getuid/getgid
strlen/strnlen/strcmp/strncmp
memcmp/memncmp/
'''


def test_concrete_value(proc, sym, value):
    if not proc.state.se.symbolic(sym):
        if proc.state.se.eval(sym) == value:
            return True
    return False


def errno_success(proc):
    return proc.state.se.If(
        'errno',
        0, -1
    )


def minmax(proc, sym, upper=None):
    min_v = proc.state.se.min(sym)
    max_v = proc.state.se.max(sym)
    if upper:
        return max(min_v, min(max_v, upper))
    return max_v