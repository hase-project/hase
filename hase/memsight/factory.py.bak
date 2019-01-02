import utils
import simple_fully_symbolic_memory
import naive_fully_symbolic_memory
import angr_symbolic_memory
import range_fully_symbolic_memory


def get_angr_symbolic_memory(angr_project):
    mem_memory = None
    reg_memory = None
    #mem_memory = angr_symbolic_memory.SymbolicMemory(angr_project.loader.memory, utils.get_permission_backer(angr_project), 'mem')
    #reg_memory = angr_symbolic_memory.SymbolicMemory(None, None, 'reg', angr_project.arch, endness=angr_project.arch.register_endness)
    return mem_memory, reg_memory


def get_simple_fully_symbolic_memory(angr_project):
    mem_memory = simple_fully_symbolic_memory.SymbolicMemory(angr_project.loader.memory, None, 'mem', None, ) # endness=proj.arch.memory_endness
    reg_memory = simple_fully_symbolic_memory.SymbolicMemory(None, None, 'reg', angr_project.arch, endness=angr_project.arch.register_endness)
    return mem_memory, reg_memory


def get_naive_fully_symbolic_memory(angr_project):
    mem_memory = naive_fully_symbolic_memory.SymbolicMemory(angr_project.loader.memory, utils.get_permission_backer(angr_project), 'mem', None, ) # endness=proj.arch.memory_endness
    reg_memory = angr_symbolic_memory.SymbolicMemory(None, None, 'reg', angr_project.arch, endness=angr_project.arch.register_endness)
    return mem_memory, reg_memory


def get_range_fully_symbolic_memory(angr_project):
    mem_memory = range_fully_symbolic_memory.SymbolicMemory(angr_project.loader.memory, utils.get_permission_backer(angr_project), 'mem', None, ) # endness=proj.arch.memory_endness
    reg_memory = angr_symbolic_memory.SymbolicMemory(None, None, 'reg', angr_project.arch, endness=angr_project.arch.register_endness)
    return mem_memory, reg_memory