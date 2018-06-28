import gdb # pylint: disable=E0401
import sys

from typing import List, Any

frame = gdb.selected_frame()
blk = frame.block()
res = [] # type: List[Any]
while not blk.is_global and not blk.is_static:
    res += [(s.name, s.type, s.value) for s in blk]
    blk = blk.superblock
    if not blk:
        break


def parse_print(s):
    # NOTE: format: $n = [(type*)] addr
    l = s.split(' ')
    # NOTE: ['$n', '=', '('qualifier', 'type', '*)', 'addr\n']
    tystr = []
    is_type = False
    n = 0
    for i in range(len(l) - 2):
        value = l[i + 2]
        if value[0] == '(':
            is_type = True
            value = value[1:]
        if value[-1] == ')':
            is_type = False
            value = value[:-1]
            indirect = len(value)
            n = i
            break
        if is_type:
            tystr.append(value)
    addr = '&'.join(l[n+3:])
    return tystr, indirect, addr


for name, ty, value in res:
    # TODO: modified to info addr arg => no rbp dependent (no parse for rbp offset 0+-n)
    tmp_str = "print &{}".format(name)
    res_str = gdb.execute(tmp_str, to_string=True)
    res_str = res_str.replace('\n', '')
    ty, idr, addr = parse_print(res_str)
    res_str = gdb.execute(
        "print sizeof({})".format(' '.join(ty) + '*' * (idr - 1)),
        to_string=True
    )
    res_str = res_str.replace('\n', '')
    size = res_str.split(' ')[-1]
    tystr = ':'.join(ty)
    print(' '.join(['ARGS:', name, tystr, str(idr), addr, size]))


