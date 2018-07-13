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


def parse_c_declaration(decl):
    pos = 0

    def get_token(pos):
        while decl[pos].isspace():
            pos += 1
        c = decl[pos]
        pos += 1
        if c == '(':
            if decl[pos] == ')':
                pos += 1
                return pos, '()', 'PARENS'
            return pos, '', '('
        elif c == '[':
            token = ''
            while decl[pos] != ']':
                token += decl[pos]
                pos += 1
            return pos, token, 'BRACKETS'
        elif c.isalpha():
            token = ''
            while decl[pos].isalnum():
                token += decl[pos]
                pos += 1
            return pos, token, 'IDENTIFIER'
        elif c == '*':
            return pos, '*', 'POINTER'
        else:
            return pos, c, 'UNKNOWN'

    pos, token, ty = get_token(pos)



def parse_addr(s):
    print(s)
    l = s.split(' ')
    # NOTE: ['$n', '=', '('qualifier', 'type', '*)', 'addr\n']
    has_type = False
    n = 0
    # array type: (char (*)[n])
    for i in range(len(l) - 2):
        value = l[i + 2]
        if value[-1] == ')':
            has_type = True
            n = i
            break
    if has_type:
        addr = '&'.join(l[n+3:])
    else:
        addr = '&'.join(l[2:])
    return addr


for name, ty, value in res:
    # TODO: modified to info addr arg => no rbp dependent (no parse for rbp offset 0+-n)
    tmp = 'ptype {}'.format(name)
    res = gdb.execute(tmp, to_string=True)
    ty = res.partition('=')[2].strip()

    tmp = "print &{}".format(name)
    res = gdb.execute(tmp, to_string=True)
    res = res.replace('\n', '')
    addr = parse_addr(res)

    res = gdb.execute(
        "print sizeof({})".format(ty),
        to_string=True
    )
    res = res.replace('\n', '')
    size = res.split(' ')[-1]
    ty = ty.replace(' ', '%')

    print(' '.join(['ARGS:', name, ty, '1', addr, size]))


