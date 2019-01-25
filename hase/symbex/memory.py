import bisect
import logging
from typing import Any, List, Optional, Union

import claripy
from angr import SimState
from angr import sim_options as so
from angr.state_plugins.sim_action import SimActionObject
from angr.storage.memory import MemoryStoreRequest, SimMemory
from angr.storage.paged_memory import SimPagedMemory
from intervaltree import IntervalTree

#from .paged_memory import PagedMemory
from ..sorted_collection import SortedCollection

l = logging.getLogger(__name__)


def get_obj_bytes(obj: Any, offset: int, size: int) -> Any:
    # full obj is needed
    if offset == 0 and size * 8 == len(obj):
        return obj, size, size

    size = min(size, (len(obj) // 8) - offset)

    # slice the object
    left = len(obj) - (offset * 8) - 1
    right = left - (size * 8) + 1
    return obj[left:right], size, size


def convert_to_ast(state: SimState, data_e: Any, size_e: Any = None) -> Any:
    """
    Make an AST out of concrete @data_e
    """
    if type(data_e) is str:
        # Convert the string into a BVV, *regardless of endness*
        bits = len(data_e) * 8
        data_e = state.solver.BVV(data_e, bits)
    elif isinstance(data_e, int):
        data_e = state.solver.BVV(
            data_e, size_e * 8 if size_e is not None else state.arch.bits
        )
    else:
        data_e = data_e.to_bv()

    return data_e


def get_unconstrained_bytes(
    state: SimState, name: str, bits: int, source: Any = None, memory: Any = None
) -> claripy.BVV:
    if (
        memory is not None
        and memory.category == "mem"
        and so.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY in state.options
    ):
        # CGC binaries zero-fill the memory for any allocated region
        # Reference: (https://github.com/CyberGrandChallenge/libcgc/blob/master/allocate.md)
        return state.solver.BVV(0x0, bits)

    return state.solver.Unconstrained(name, bits)


def _raw_ast(a: Any) -> Any:
    if isinstance(a, SimActionObject):
        return a.ast
    elif type(a) is dict:
        return {k: _raw_ast(a[k]) for k in a}
    elif type(a) in (tuple, list, set, frozenset):
        return type(a)((_raw_ast(b) for b in a))
    else:
        return a


class MemoryItem:
    __slots__ = ("addr", "_obj", "t", "guard")

    def __init__(self, addr: int, obj: Any, t: Any, guard: Any) -> None:
        self.addr = addr
        self._obj = obj
        self.t = t
        self.guard = guard

    @property
    def obj(self) -> Any:
        if isinstance(self._obj, list):
            self._obj = get_obj_bytes(self._obj[0], self._obj[1], 1)[0]
        return self._obj

    def __repr__(self) -> str:
        return (
            "["
            + str(self.addr)
            + ", "
            + str(self.obj)
            + ", "
            + str(self.t)
            + ", "
            + str(self.guard)
            + "]"
        )

    def _compare_obj(self, other: "MemoryItem") -> bool:
        if id(self._obj) == id(other._obj):
            return True

        if (
            type(self._obj) in (list,)
            and type(other._obj) in (list,)
            and id(self._obj[0]) == id(other._obj[0])
            and self._obj[1] == self._obj[1]
        ):
            return True

        if type(self._obj) in (list,):
            if type(self._obj[0]) not in (claripy.ast.bv.BV,):
                return False
        elif type(self._obj) not in (claripy.ast.bv.BV,):
            return False

        if isinstance(other._obj, list):
            if type(other._obj[0]) not in (claripy.ast.bv.BV,):
                return False
        elif type(other._obj) not in (claripy.ast.bv.BV,):
            return False

        a = self.obj
        b = other.obj
        if a.op == "BVV" and b.op == "BVV":
            return a.args[0] == b.args[0]

        return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MemoryItem):
            return False

        if id(self) == id(other):
            return True

        if (
            other is None
            or self.t != other.t
            # or (type(self.addr) in (int, long) and type(other.addr) in (int, long) and self.addr != other.addr)
            or (
                isinstance(self.obj, int)
                and isinstance(other.obj, int)
                and self.obj != other.obj
            )
            or id(self.guard) != id(other.guard)  # conservative
            or not self._compare_obj(other)
        ):
            return False

        return True

    def copy(self) -> "MemoryItem":
        return MemoryItem(self.addr, self.obj, self.t, self.guard)


class SymbolicMemory(SimMemory):
    def __init__(
        self,
        memory_backer: Any = None,
        permissions_backer: Any = None,
        mem: Any = None,
        memory_id: str = "mem",
        endness: Any = None,
        abstract_backer: Any = False,
        check_permissions: Any = None,
        read_strategies: Any = None,
        write_strategies: Any = None,
        stack_region_map: Any = None,
        generic_region_map: Any = None,
        concrete_memory: Optional[SimPagedMemory] = None,
        symbolic_memory: Optional[IntervalTree] = None,
        timestamp: int = 0,
        timestamp_implicit: int = 0,
        initializable: Optional[SortedCollection] = None,
        initialized: bool = False,
    ) -> None:
        SimMemory.__init__(
            self,
            endness=endness,
            abstract_backer=abstract_backer,
            stack_region_map=stack_region_map,
            generic_region_map=generic_region_map,
        )
        self.id = memory_id

        self.timestamp = timestamp
        self.timestamp_implicit = timestamp_implicit

        if concrete_memory is None:
            self._concrete_memory = SimPagedMemory(self)  # type: SimPagedMemory
        else:
            self._concrete_memory = concrete_memory

        if symbolic_memory is None:
            self._symbolic_memory = IntervalTree()
        else:
            self._symbolic_memory = symbolic_memory

        if initializable is None:
            self._initializable = SortedCollection(key=lambda x: x[0])
        else:
            self._initializable = initializable

        self._initialized = initialized

    def copy(self, _: Any) -> "SymbolicMemory":
        mem = SymbolicMemory(
            memory_id=self.id,
            endness=self.endness,
            abstract_backer=self._abstract_backer,
            stack_region_map=self._stack_region_map,
            generic_region_map=self._generic_region_map,
            concrete_memory=self._concrete_memory,  # we do it properly below...
            symbolic_memory=self._symbolic_memory.copy(),
            timestamp=self.timestamp,
            timestamp_implicit=self.timestamp_implicit,
            initializable=self._initializable.copy(),
            initialized=self._initialized,
        )

        mem._concrete_memory = self._concrete_memory.copy(mem)
        return mem

    @property
    def mem(self) -> "SymbolicMemory":
        # In angr, this returns a reference to the (internal) paged memory
        # We do not have (yet) a paged memory. We instead return self
        # that exposes a _preapproved_stack attribute
        # (similarly as done by a paged memory)
        return self

    def _load_init_data(self, addr: int, size: int) -> None:
        page_size = 0x1000
        page_index = int(addr / page_size)
        page_end = int((addr + size) / page_size)
        k = bisect.bisect_left(self._initializable._keys, page_index)

        to_remove = []
        while k < len(self._initializable) and self._initializable[k][0] <= page_end:

            data = self._initializable[
                k
            ]  # [page_index, data, data_offset, page_offset, min(size, page_size]
            page = (
                self._concrete_memory._pages[data[0]]
                if data[0] in self._concrete_memory._pages
                else None
            )
            for j in range(data[4]):

                if page is not None and data[3] + j in page:
                    continue

                e = (data[0] * 0x1000) + data[3] + j
                v = [data[1], data[2] + j]
                self._concrete_memory[e] = MemoryItem(e, v, 0, None)

            to_remove.append(data)
            k += 1

        for e in to_remove:
            self._initializable.remove(e)

    def __contains__(self, dst: Union[claripy.BVV, int]) -> bool:
        if isinstance(dst, int):
            addr = dst
        elif self.state.solver.symbolic(dst):
            l.warning(
                "Currently unable to do SimMemory.__contains__ on symbolic variables."
            )
            return False
        else:
            addr = self.state.solver.eval(dst)

        return addr in self._concrete_memory or addr in self._symbolic_memory

    def build_merged_ite(self, addr: int, P: Any, obj: Any) -> Any:
        N = len(P)
        merged_p = []  # type: List[Any]
        for i in range(N):
            p = P[i]
            v = p.obj

            is_good_candidate = isinstance(p.addr, int) and p.guard is None
            mergeable = False
            if (
                len(merged_p) > 0
                and is_good_candidate
                and p.addr == merged_p[-1].addr + 1
            ):
                prev_v = merged_p[-1].obj
                if v.op == "BVV":

                    # both constant and equal
                    if prev_v.op == "BVV" and v.args[0] == prev_v.args[0]:
                        mergeable = True

                # same symbolic object
                elif v is prev_v:
                    mergeable = True

            if not mergeable:
                if len(merged_p) > 0:
                    obj = self.build_ite(addr, merged_p, merged_p[-1].obj, obj)
                    merged_p = []

                if is_good_candidate:
                    merged_p.append(p)
                else:
                    obj = self.build_ite(addr, [p], v, obj)
            else:
                merged_p.append(p)

        if len(merged_p) > 0:
            obj = self.build_ite(addr, merged_p, merged_p[-1].obj, obj)

        return obj

    def build_ite(self, addr: int, cases: Any, v: Any, obj: Any) -> Any:
        assert len(cases) > 0

        if len(cases) == 1:
            cond = addr == cases[0].addr
        else:
            cond = self.state.solver.And(addr >= cases[0].addr, addr <= cases[-1].addr)

        if cases[0].guard is not None:
            cond = claripy.And(cond, cases[0].guard)

        return self.state.solver.If(cond, v, obj)

    def _store(self, req: MemoryStoreRequest) -> None:
        if req.condition is not None:
            if self.state.solver.is_true(req.condition):
                req.condition = None
            elif self.state.solver.is_false(req.condition):
                return

        condition = _raw_ast(req.condition)
        condition = self.state._adjust_condition(req.condition)

        # store with conditional size
        conditional_size = None
        if req.size.symbolic:
            conditional_size = [
                self.state.solver.min_int(req.size),
                self.state.solver.max_int(req.size),
            ]
            self.state.solver.add(self.state.solver.ULE(req.size, conditional_size[1]))
            size = conditional_size[1]
        else:
            size = self.state.solver.eval(req.size)

        # convert data to BVV if concrete
        data = convert_to_ast(
            self.state, req.data, req.size if isinstance(req.size, int) else None
        )
        assert len(data) // 8 == size

        # simplify
        data = self.state.solver.simplify(data)

        # fix endness
        if req.endness is None:
            req.endness = self._endness

        if req.endness == "Iend_LE":
            data = data.reversed

        if req.addr.concrete:
            min_addr = self.state.solver.eval(req.addr)
            max_addr = min_addr
        else:  # symbolic addr
            min_addr = self.state.solver.min_int(req.addr)
            max_addr = self.state.solver.max_int(req.addr)
            if min_addr == max_addr:
                addr = min_addr

        self.timestamp += 1

        initial_condition = condition

        for k in range(size):
            obj = [data, k]
            if req.size.concrete and size == 1:
                obj = data

            if conditional_size is not None and k + 1 >= conditional_size[0]:
                assert k + 1 <= conditional_size[1]

                if initial_condition is None:
                    condition = self.state.solver.UGT(req.size, k)
                else:
                    condition = claripy.And(
                        initial_condition, self.state.solver.UGT(req.size, k + 1)
                    )

            inserted = False

            if min_addr == max_addr:
                P = self._concrete_memory[min_addr + k]
                if P is None or condition is None:
                    self._concrete_memory[min_addr + k] = MemoryItem(
                        min_addr + k, obj, self.timestamp, condition
                    )

                else:
                    item = MemoryItem(min_addr + k, obj, self.timestamp, condition)
                    if isinstance(P, list):
                        P = [item] + P
                    else:
                        P = [item, P]
                    self._concrete_memory[min_addr + k] = P

                inserted = True

            if not inserted:
                if condition is None:
                    P = self._symbolic_memory.search(min_addr + k, max_addr + k + 1)
                    for p in P:
                        if id(p.data.addr) == id(
                            addr + k
                        ):  # this check is pretty useless...
                            self._symbolic_memory.update_item(
                                p, MemoryItem(addr + k, obj, self.timestamp, None)
                            )
                            inserted = True
                            break

            if not inserted:
                self._symbolic_memory.add(
                    min_addr + k,
                    max_addr + k + 1,
                    MemoryItem(addr + k, obj, self.timestamp, condition),
                )

        req.completed = True
        return

    def _load(
        self,
        addr: Any,
        size: Any,
        condition: Any = None,
        fallback: Any = None,
        inspect: bool = True,
        events: bool = True,
        ret_on_segv: bool = False,
    ) -> Any:
        if isinstance(size, int):
            # concrete address
            if isinstance(addr, int):
                min_addr = addr
                max_addr = addr
            else:
                min_addr = self.state.solver.min_int(addr)
                max_addr = self.state.solver.max_int(addr)
                if min_addr == max_addr:
                    addr = min_addr

            # check if binary data should be loaded into address space
            self._load_init_data(min_addr, (max_addr - min_addr) + size)

            data = None
            for k in range(size):

                P = self._concrete_memory.find(min_addr + k, max_addr + k)
                P += [
                    x.data
                    for x in self._symbolic_memory.search(
                        min_addr + k, max_addr + k + 1
                    )
                ]
                P = sorted(
                    P, key=lambda x: (x.t, (x.addr if isinstance(x.addr, int) else 0))
                )

                if (
                    min_addr == max_addr
                    and len(P) == 1
                    and isinstance(P[0].addr, int)
                    and P[0].guard is None
                ):
                    obj = P[0].obj

                else:

                    obj = get_unconstrained_bytes(self.state, "bottom", 8, memory=self)

                    if (
                        self.category == "mem"
                        and so.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY
                        not in self.state.options
                    ):
                        # implicit store...
                        self.timestamp_implicit -= 1
                        self._symbolic_memory.add(
                            min_addr + k,
                            max_addr + k + 1,
                            MemoryItem(addr + k, obj, self.timestamp_implicit, None),
                        )

                    obj = self.build_merged_ite(addr + k, P, obj)

                # concat single-byte objs
                data = self.state.solver.Concat(data, obj) if data is not None else obj

            if condition is not None:
                assert fallback is not None
                condition = self._raw_ast(condition)
                fallback = self._raw_ast(fallback)
                data = self.state.solver.If(condition, data, fallback)

            return data
        assert False
