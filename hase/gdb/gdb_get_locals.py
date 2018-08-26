import gdb # pylint: disable=E0401
import sys

from typing import List, Any

frame = gdb.selected_frame()
blk = frame.block()
res = [] # type: List[Any]
names = set()
while not blk.is_global and not blk.is_static:
    print(blk, blk.function)
    print([s.name for s in blk])
    [names.add(s.name) for s in blk]
    # NOTE: if the function is inlined, we shall stop here
    if blk.function:
        if blk.function.name in names:
            names.remove(blk.function.name)
        break
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


for name in names:
    # TODO: modified to info addr arg => no rbp dependency (no parse for rbp offset 0+-n)
    try:
        tmp = 'ptype {}'.format(name)
        result = gdb.execute(tmp, to_string=True)
    except:
        print(' '.join(['ARGS:', name, 'unknown', '-2', '0', '0']))
        continue
    ty = result.partition('=')[2].strip()
    # NOTE: struct Ty { ... } *
    if ty.find('{') != -1:
        left_b = ty.find('{')
        right_b = len(ty) - ty[::-1].find('}') - 1
        ty = ty[0:left_b].strip() + ' ' + ty[right_b+1:].strip()

    result = gdb.execute(
        "print sizeof({})".format(ty),
        to_string=True
    )
    result = result.replace('\n', '')
    size = result.split(' ')[-1]
    ty = ty.replace(' ', '%')

    try:
        tmp = "print &{}".format(name)
        result = gdb.execute(tmp, to_string=True)
        result = result.replace('\n', '')
        addr = parse_addr(result)
        print(' '.join(['ARGS:', name, ty, '1', addr, size]))
    except Exception as ex:
        err = str(ex)
        # NOTE: non-lvalue case and register case
        # Can't take address of \"var\" which isn't an lvalue
        if "lvalue" in err:
            print(' '.join(['ARGS:', name, ty, '-1', '0', size]))
        # Address requested for identifier \"id\" which is in register $rax
        elif "Address requested" in err:
            reg = err.split('$')[-1]
            print(' '.join(['ARGS:', name, ty, '2', reg, size]))



