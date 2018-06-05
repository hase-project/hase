import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES


# TODO: getgrgid, getgrnam, getgrent, endgrent, setgrent, 
# getgrgid_r, getgrnam_r


class getgrgid(SimProcedure):
    def run(self, gid):
        malloc = SIM_PROCEDURES['libc']['malloc']
        ret_addr = self.inline_call(malloc, 0x18).ret_expr
        self._store_amd64(ret_addr)
        return ret_addr

    def _store_amd64(self, group_buf):
        store = lambda offset, val: self.state.memory.store(group_buf + offset, val)
        # TODO: complete struct group member
        '''
        struct group {
            char* gr_name; // name of the group
            gid_t gr_gid; // group ID, gid_t = 4 bytes
            char** gr_mem; // pointer to a null-terminated array of character 
                pointers to member names.
        }
        '''
        pass
        