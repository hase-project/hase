import angr


def get_permission_backer(proj):
    permission_map = { }
    for obj in proj.loader.all_objects:
        for seg in obj.segments:
            perms = 0
            # bit values based off of protection bit values from sys/mman.h
            if seg.is_readable:
                perms |= 1 # PROT_READ
            if seg.is_writable:
                perms |= 2 # PROT_WRITE
            if seg.is_executable:
                perms |= 4 # PROT_EXEC
            try:
                permission_map[(obj.rebase_addr + seg.min_addr, obj.rebase_addr + seg.max_addr)] = perms
            except Exception as e:
                pass
    return (proj.loader.main_object.execstack, permission_map)


def parse_args(argv):
    if len(argv) < 2 or len(argv) > 3:
        print(("python " + sys.argv[0] + " [0|1] binary"))
        sys.exit(1)

    t = 0
    file = argv[1]
    if len(argv) == 3:
        t = int(argv[1])
        assert t == 0 or t == 1 or t == 2 or t == 3
        file = argv[2]

    return t, file


def get_unconstrained_bytes(state, name, bits, source=None, memory=None):

    if (memory is not None and memory.category == 'mem' and
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY in state.options):
        # CGC binaries zero-fill the memory for any allocated region
        # Reference: (https://github.com/CyberGrandChallenge/libcgc/blob/master/allocate.md)
        #if memory.verbose: memory.log("\treturning zero-valued unconconstrained bytes")
        return state.se.BVV(0x0, bits)

    #if memory.verbose: memory.log("\treturning fully unconconstrained bytes")
    return state.se.Unconstrained(name, bits)


def get_obj_bytes(obj, offset, size):

    # full obj is needed
    if offset == 0 and size * 8 == len(obj):
        return obj, size, size

    size = min(size, (len(obj) / 8) - offset)

    # slice the object
    left = len(obj) - (offset * 8) - 1
    right = left - (size * 8) + 1
    return obj[left:right], size, size


def convert_to_ast(state, data_e, size_e=None):
    """
    Make an AST out of concrete @data_e
    """
    if type(data_e) is str:
        # Convert the string into a BVV, *regardless of endness*
        bits = len(data_e) * 8
        data_e = state.se.BVV(data_e, bits)
    elif type(data_e) in (int, int):
        data_e = state.se.BVV(data_e, size_e*8 if size_e is not None else state.arch.bits)
    else:
        data_e = data_e.to_bv()

    return data_e

def resolve_location_name(memory, name):

    stn_map = { 'st%d' % n: n for n in range(8) }
    tag_map = { 'tag%d' % n: n for n in range(8) }

    if memory.category == 'reg':
        if memory.state.arch.name in ('X86', 'AMD64'):
            if name in stn_map:
                return (((stn_map[name] + memory.load('ftop')) & 7) << 3) + memory.state.arch.registers['fpu_regs'][0], 8
            elif name in tag_map:
                return ((tag_map[name] + memory.load('ftop')) & 7) + memory.state.arch.registers['fpu_tags'][0], 1

        return memory.state.arch.registers[name]
    elif name[0] == '*':
        return memory.state.registers.load(name[1:]), None
    else:
        raise angr.errors.SimMemoryError("Trying to address memory with a register name.")

def reverse_addr_reg(memory, addr):

    assert memory.category == 'reg'
    assert type(addr) in (int, int)

    for name, offset_size in list(memory.state.arch.registers.items()):
        offset = offset_size[0]
        size = offset_size[1]
        if addr in range(offset, offset + size):
            return name

    assert False

def full_stack():

    import traceback, sys
    exc = sys.exc_info()[0]
    stack = traceback.extract_stack()[:-1]  # last one would be full_stack()
    if not exc is None:     # i.e. if an exception is present
        del stack[-1]       # remove call of full_stack, the printed exception
                            # will contain the caught exception caller instead
    trc = 'Traceback (most recent call last):\n'
    stackstr = trc + ''.join(traceback.format_list(stack))
    if not exc is None:
         stackstr += '  ' + traceback.format_exc().lstrip(trc)
    return stackstr
