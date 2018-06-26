import gdb # pylint: disable=E0401
import sys

frame = gdb.selected_frame()
blk = frame.block()
res = [(s.name, s.type, s.value) for s in blk]


def parse_print(s):
    # NOTE: format: $n = [(type*)] addr
    l = s.split(' ')
    # NOTE: ['$n', '=', '('qualifier', 'type', '*)', 'addr\n']
    tystr = []
    is_type = False
    for i in range(len(l) - 2):
        value = l[i + 2]
        if value[0] == '(':
            is_type = True
            value = value[1:]
        if value[-1] == ')':
            is_type = False
            value = value[:-1]
            indirect = len(value)
        if is_type:
            tystr.append(value)
    addr = l[-1].strip()
    return tystr, indirect, addr


for name, ty, value in res:
    # TODO: modified to info addr arg => no rbp dependent (no parse for rbp offset 0+-n)
    tmp_str = "print &{}".format(name)
    res_str = gdb.execute(tmp_str, to_string=True)
    ty, idr, addr = parse_print(res_str)
    tystr = '_'.join(ty)
    print(' '.join(['ARGS:', name, tystr, str(idr), addr]))


