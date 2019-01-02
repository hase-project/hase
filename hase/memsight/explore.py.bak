import executor
import sys
import factory
import utils
import logging

if __name__ == '__main__':

    #logging.getLogger('angr').setLevel(logging.DEBUG)
    #logging.getLogger('simuvex').setLevel(logging.DEBUG)

    logging.getLogger('angr.analyses.veritesting').setLevel(logging.DEBUG)

    t, file = utils.parse_args(sys.argv)

    explorer = executor.Executor(file)
    angr_project = explorer.project

    if t == 0:
        mem_memory, reg_memory = factory.get_simple_fully_symbolic_memory(angr_project)
    elif t == 1:
        mem_memory, reg_memory = factory.get_angr_symbolic_memory(angr_project)
    elif t == 2:
        mem_memory, reg_memory = factory.get_naive_fully_symbolic_memory(angr_project)
        mem_memory.verbose = True
    elif t == 3:
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(angr_project)
        mem_memory.verbose = True

    explorer.explore(mem_memory = mem_memory, reg_memory = reg_memory)