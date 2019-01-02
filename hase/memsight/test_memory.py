import angr
from . import factory
import simuvex
import claripy
import sys

def check(state, obj, exp_values, conditions):
    r = state.se.any_n_int(obj, len(exp_values) + 1, extra_constraints=conditions)
    if len(r) != len(exp_values) or set(r) != set(exp_values):
        print("Mismatch:")
        print(("\tobtained: " + str(r)))
        print(("\texpected: " + str(exp_values)))
    assert len(r) == len(exp_values) and set(r) == set(exp_values)

def test_store_with_symbolic_size(state):

    val = 0x01020304
    state.memory.store(0x0, claripy.BVV(val, 32))
    res = state.memory.load(0x0, 4)
    assert not state.se.symbolic(res) and state.se.any_int(res) == val

    val_2 = 0x0506
    s_size = claripy.BVS('size', 32)
    state.se.add(s_size <= 2)
    state.memory.store(0x1, claripy.BVV(val_2, 16), s_size)
    res = state.se.any_n_int(state.memory.load(0x0, 4), 10)
    print((' '.join([hex(x) for x in res])))
    assert len(state.se.any_n_int(state.memory.load(0x0, 4), 10)) == 3

    s0 = state.copy()
    assert len(s0.se.any_n_int(s0.memory.load(0x0, 4), 10)) == 3

    s1 = state.copy()
    s1.se.add(s_size == 0)
    res = s1.se.any_n_int(s1.memory.load(0x0, 4), 2)
    assert len(res) == 1 and res[0] == val

    s2 = state.copy()
    s2.se.add(s_size == 1)
    res = s2.se.any_n_int(s2.memory.load(0x0, 4), 2)
    assert len(res) == 1 and res[0] == 0x01050304

    s3 = state.copy()
    s3.se.add(s_size == 2)
    res = s3.se.any_n_int(s3.memory.load(0x0, 4), 2)
    assert len(res) == 1 and res[0] == 0x01050604


def test_store_with_symbolic_addr_and_symbolic_size(state):

    #state.memory.set_verbose(True)

    val = 0x01020304
    addr = claripy.BVS('addr', 64)
    state.se.add(addr < 8)
    state.memory.store(addr, claripy.BVV(val, 32))
    res = state.memory.load(addr, 4)
    res = state.se.any_n_int(res, 20)
    assert len(res) == 1 and res[0] == val

    val_2 = 0x0506
    s_size = claripy.BVS('size', 32)
    state.se.add(s_size <= 2)
    state.memory.store(addr + 1, claripy.BVV(val_2, 16), s_size)

    s0 = state.copy()
    assert len(s0.se.any_n_int(s0.memory.load(addr, 4), 10)) == 3

    s1 = state.copy()
    s1.se.add(s_size == 0)
    res = s1.se.any_n_int(s1.memory.load(addr, 4), 2)
    assert len(res) == 1 and res[0] == val

    s2 = state.copy()
    s2.se.add(s_size == 1)
    res = s2.se.any_n_int(s2.memory.load(addr, 4), 2)
    assert len(res) == 1 and res[0] == 0x01050304

    s3 = state.copy()
    s3.se.add(s_size == 2)
    res = s3.se.any_n_int(s3.memory.load(addr, 4), 2)
    assert len(res) == 1 and res[0] == 0x01050604

def test_concrete_merge(state):

    val = 0x01020304
    state.memory.store(0x0, claripy.BVV(val, 32))

    s1 = state.copy()
    s2 = state.copy()

    s1.memory.store(0x1, claripy.BVV(0x05, 8))
    s2.memory.store(0x1, claripy.BVV(0x06, 8))

    s3 = s1.copy()
    guard = claripy.BVS('branch', 32)
    s3.memory.merge([s2.memory], [guard > 0, guard <= 0], s1.memory)

    res = s3.memory.load(0x0, 4)

    r1 = s3.se.any_n_int(res, 2, extra_constraints=(guard > 0,))
    assert len(r1) == 1 and r1[0] == 0x01050304

    r2 = s3.se.any_n_int(res, 2, extra_constraints=(guard <= 0,))
    assert len(r2) == 1 and r2[0] == 0x01060304

def test_concrete_merge_with_condition(state):

    val = 0x01020304
    state.memory.store(0x0, claripy.BVV(val, 32))

    s1 = state.copy()
    s2 = state.copy()

    s1.memory.store(0x1, claripy.BVV(0x05, 8))

    cond = claripy.BVS('cond', 32)
    s2.memory.store(0x1, claripy.BVV(0x06, 8), condition=cond != 0)

    s3 = s1.copy()
    guard = claripy.BVS('guard', 32)
    s3.memory.merge([s2.memory], [guard > 1, guard <= 1], s1.memory)

    res = s3.memory.load(0x0, 4)

    r1 = s3.se.any_n_int(res, 2, extra_constraints=(guard > 1,))
    assert len(r1) == 1 and r1[0] == 0x01050304

    r2 = s3.se.any_n_int(res, 3, extra_constraints=(guard <= 1,))
    assert len(r2) == 2 and set(r2) == set([0x01020304, 0x01060304])

    s4 = s3.copy()
    s4.se.add(guard == 1)
    s4.se.add(cond != 0)
    res = s4.memory.load(0x0, 4)
    r3 = s4.se.any_n_int(res, 2)
    assert len(r3) == 1 and r3[0] == 0x01060304

def test_symbolic_merge(state):

    val = 0x01020304
    state.memory.store(0x0, claripy.BVV(val, 32))

    a = claripy.BVS('a0', 64)
    state.se.add(a <= 1)
    state.memory.store(a, claripy.BVV(0x5, 8))

    s1 = state.copy()
    s1.memory.store(0x1, claripy.BVV(0x6, 8))
    a1 = claripy.BVS('a1', 64)
    s1.se.add(a1 >= 1)
    s1.se.add(a1 <= 2)
    s1.memory.store(a1, claripy.BVV(0x7, 8))

    s2 = state.copy()
    s2.memory.store(0x1, claripy.BVV(0x8, 8))
    a2 = claripy.BVS('a2', 64)
    s2.se.add(a2 >= 1)
    s2.se.add(a2 <= 2)
    s2.memory.store(a2, claripy.BVV(0x9, 8))

    s3 = s1.copy()
    guard = claripy.BVS('guard', 32)
    s3.memory.merge([s2.memory], [guard > 1, guard <= 1], s1.memory)

    res = s3.memory.load(0x0, 1)
    check(state, res, [5], (a == 0,))
    check(state, res, [1], (a == 1,))

    res = s3.memory.load(0x1, 1)
    check(state, res, [7], (guard > 1, a1 == 1, ))
    check(state, res, [6], (guard > 1, a1 == 2,))
    check(state, res, [9], (guard <= 1, a2 == 1,))
    check(state, res, [8], (guard <= 1, a2 == 2,))

    res = s3.memory.load(0x2, 1)
    check(state, res, [7], (guard > 1, a1 == 2,))
    check(state, res, [3], (guard > 1, a1 == 1,))
    check(state, res, [9], (guard <= 1, a2 == 2,))
    check(state, res, [3], (guard <= 1, a2 == 1,))

    res = s3.memory.load(0x3, 1)
    check(state, res, [4], set())

def test_symbolic_access(state):

    endness = "Iend_LE"

    # an address which is in a valid region
    start_addr = state.libc.heap_location
    state.libc.heap_location += 32  # mark 32 bytes as used

    #assert state.se.any_int(state.memory.permissions(start_addr)) == 0x3
    #assert state.se.any_int(state.memory.permissions(start_addr + 1)) == 0x3
    #assert state.se.any_int(state.memory.permissions(start_addr + 2)) == 0x3

    # init memory 3 bytes starting at start_addr
    state.memory.store(start_addr, claripy.BVV(0x0, 24), 3, endness=endness)

    # a symbolic pointer that can be equal to [start_addr, start_addr + 1]
    addr = claripy.BVS('addr', 64)
    state.se.add(addr >= start_addr)
    state.se.add(addr <= start_addr + 1)
    addrs = state.se.any_n_int(addr, 10)
    assert len(addrs) == 2 and set(addrs) == set([start_addr, start_addr + 1])

    val = 0xABCD

    # symbolic store at addr
    state.memory.store(addr, claripy.BVV(val, 16), 2, endness=endness)

    # symbolic load at addr
    res = state.memory.load(addr, 2, endness=endness)
    res = state.se.any_n_int(res, 20)
    assert len(res) == 1 and res[0] == val


def test_same_operator(state):

    a = claripy.BVS('a', 8)
    b = claripy.BVS('b', 8)

    assert not state.memory.same(a, b)

    state.se.add(a == b)

    assert state.memory.same(a, b)

    state.se.add(a < 5)

    assert state.memory.same(a, b)

    zero = claripy.BVV(0x0, 8)
    assert not state.memory.same(a, zero)

    state.se.add(a < 1)

    assert state.memory.same(a, zero)



if __name__ == '__main__':

    t = 3
    angr_project = angr.Project("/bin/ls", load_options={'auto_load_libs': False})

    if t == 0:
        mem_memory, reg_memory = factory.get_simple_fully_symbolic_memory(angr_project)
    elif t == 1:
        mem_memory, reg_memory = None, None
    elif t == 2:
        mem_memory, reg_memory = factory.get_naive_fully_symbolic_memory(angr_project)
    elif t == 3:
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(angr_project)
        #mem_memory.set_verbose(True)

    plugins = {}
    if mem_memory is not None:
        plugins['memory'] = mem_memory
    if reg_memory is not None:
        plugins['registers'] = reg_memory

    add_options = {None}
    #add_options = {simuvex.o.STRICT_PAGE_ACCESS}
    # add_options = {simuvex.o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY}

    state = angr_project.factory.entry_state(remove_options={simuvex.o.LAZY_SOLVES},
                                             add_options=add_options, plugins=plugins)
    if t == 1:
        # store: add new concretization strategy
        state.memory.write_strategies.insert(0, simuvex.concretization_strategies.SimConcretizationStrategyRange(2048))
        state.memory.read_strategies.insert(0, simuvex.concretization_strategies.SimConcretizationStrategyRange(2048))

    #test_symbolic_access(state.copy())

    #test_store_with_symbolic_size(state.copy())
    #test_store_with_symbolic_addr_and_symbolic_size(state.copy())

    #test_concrete_merge(state.copy())
    #test_concrete_merge_with_condition(state.copy())

    #test_symbolic_merge(state.copy())

    if t == 3:
        test_same_operator(state.copy())
        pass
