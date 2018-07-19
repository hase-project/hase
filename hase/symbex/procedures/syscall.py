import claripy
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.errors import SimProcedureError
from angr.storage.file import Flags

from .helper import *
from .sym_struct import * # pylint: disable=W0614

class rt_sigaction(SimProcedure):
    IS_SYSCALL = True

    def run(self, signum, act, oldact):
        # TODO: do real signal registery?
        if not test_concrete_value(self, oldact, 0):
            sigaction(oldact).store_all(self)
        return errno_success(self)


class rt_sigprocmask(SimProcedure):
    IS_SYSCALL = True

    def run(self, how, set, oldset):
        # TODO: do real signal registery?
        if not test_concrete_value(self, oldset, 0):
            self.state.memory.store(oldset, self.state.se.Unconstrained('oldset', 128 * 8, uninitialized=False))
        return errno_success(self)
            

class connect(SimProcedure):
    IS_SYSCALL = True

    def run(self, sockfd, addr, addrlen):
        # NOTE: recv from angr == read, so connect does nothing
        # FIXME: actually angr.posix has open_socket and socket_queue
        new_filename = '/tmp/angr_implicit_%d' % self.state.posix.autotmp_counter
        self.state.posix.autotmp_counter += 1
        self.state.posix.open(new_filename, Flags.O_RDWR, preferred_fd=sockfd)
        return errno_success(self)
        

class access(SimProcedure):
    IS_SYSCALL = True

    def run(self, pathname, mode):
        return self.state.se.Unconstrained("access", 32, uninitialized=False)


class getgroups(SimProcedure):
    IS_SYSCALL = True

    def run(self, size, list):
        # TODO: actually read groups to state
        return self.state.se.Unconstrained('getgroups', 32, uninitialized=False)


class setgroups(SimProcedure):
    IS_SYSCALL = True

    def run(self, size, list):
        # TODO: actually set groups to state
        return errno_success(self)


class getdents(SimProcedure):
    IS_SYSCALL = True

    def run(self, fd, dirp, count):
        linux_dirent(dirp).store_all(self)
        return errno_success(self)


class getdents64(SimProcedure):
    IS_SYSCALL = True

    def run(self, fd, dirp, count):
        linux_dirent64(dirp).store_all(self)
        return errno_success(self)


class getpriority(SimProcedure):
    IS_SYSCALL = True
    
    def run(self, which, who):
        '''
        The value which is one of PRIO_PROCESS, PRIO_PGRP, or PRIO_USER, and
        who is interpreted relative to which (a process identifier for
        PRIO_PROCESS, process group identifier for PRIO_PGRP, and a user ID
        for PRIO_USER).  A zero value for who denotes (respectively) the
        calling process, the process group of the calling process, or the
        real user ID of the calling process.
        '''
        return self.state.se.Unconstrained('getpriority', 32, uninitialized=False)


class setpriority(SimProcedure):
    IS_SYSCALL = True

    def run(self, which, who, prio):
        # TODO: add priority to state
        return errno_success(self)


class arch_prctl(SimProcedure):
    IS_SYSCALL = True
    
    ARCH_SET_GS = 0x1001
    ARCH_SET_FS = 0x1002
    ARCH_GET_FS = 0x1003
    ARCH_GET_GS = 0x1004

    def run(self, code, addr):
        if self.state.se.symbolic(code):
            raise Exception("what to do here?")
        if test_concrete_value(self, code, self.ARCH_SET_GS):
            self.state.regs.gs = addr
        elif test_concrete_value(self, code, self.ARCH_SET_FS):
            self.state.regs.fs = addr
        elif test_concrete_value(self, code, self.ARCH_GET_GS):
            self.state.memory.store(addr, self.state.regs.gs)
        elif test_concrete_value(self, code, self.ARCH_GET_FS):
            self.state.memory.store(addr, self.state.regs.Fs)
        return errno_success(self)


class set_tid_address(SimProcedure):
    IS_SYSCALL = True

    def run(self, tidptr):
        # Currently we have no multiple process
        # so no set_child_tid or clear_child_tid
        return self.state.se.Unconstrained('set_tid_address', 32, uninitialized=False)

    
class kill(SimProcedure):
    IS_SYSCALL = True

    def run(self, pid, sig):
        # TODO: manager signal
        return errno_success(self)


class get_robust_list(SimProcedure):
    IS_SYSCALL = True

    def run(self, head, length):
        self.state.memory.store(head, self.state.robust_list_head)
        self.state.memory.store(length, self.state.robust_list_size)
        return errno_success(self)


class set_robust_list(SimProcedure):
    IS_SYSCALL = True

    def run(self, head, length):
        self.state.robust_list_head = head
        self.state.libc.max_robust_size = 0x20
        if self.state.se.symbolic(length):
            length = minmax(self, length, self.state.libc.max_robust_size)
        else:
            length = self.state.se.eval(length)
        self.state.robust_list_size = length
        for i in range(length):
            robust_list_head(head + i * robust_list_head.size).store_all(self) # pylint: disable=E1101
        return errno_success(self)


class nanosleep(SimProcedure):
    IS_SYSCALL = True

    def run(self, req, rem):
        timespec(rem).store_all(self)
        return errno_success(self)


class sysinfo(SimProcedure):
    IS_SYSCALL = True

    def run(self, info):
        sysinfo_t(info).store_all(self)
        return errno_success(self)


class execve(SimProcedure):
    IS_SYSCALL = True

    def run(self, filename, argv, envp):
        # TODO: do nothing here
        return errno_success(self)


class exit_group(SimProcedure):
    IS_SYSCALL = True
    NO_RET = True

    def run(self, status):
        self.exit(status)


class futex(SimProcedure):
    IS_SYSCALL = True

    def run(self, uaddr, futex_op, val, timeout, uaddr2, val3):
        # do nothing
        return self.state.se.Unconstrained('futex', 32, uninitialized=False)


class readlink(SimProcedure):
    IS_SYSCALL = True

    def run(self, path, buf, bufsize):
        self.state.memory.store(buf, self.state.se.Unconstrained('readlink', bufsize * 8, uninitialized=False))
        return errno_success(self)

    
class alarm(SimProcedure):
    IS_SYSCALL = True

    def run(self, seconds):
        return self.state.se.Unconstrained('alarm', 32, uninitialized=False)


class getpid(SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained('getpid', 32, uninitialized=False)


class getppid(SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained('getppid', 32, uninitialized=False)


class getgid(SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained('getgid', 32, uninitialized=False)


class getpgid(SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained('getpgid', 32, uninitialized=False)


class getuid(SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained('getuid', 32, uninitialized=False)


class getgrp(SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained('getgrp', 32, uninitialized=False)


class getpgrp(SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained('getpgrp', 32, uninitialized=False)


class ioctl(SimProcedure):
    IS_SYSCALL = True
    ARGS_MISMATCH = True
    def run(self, fd, request):
        return errno_success(self)


class openat(SimProcedure):
    IS_SYSCALL = True

    def run(self, dirfd, pathname, flags, mode=0644):
        xopen = SIM_PROCEDURES['posix']['open']
        # XXX: Actually name is useless, we just want to open a SimFile
        return self.inline_call(xopen, pathname, flags, mode).ret_expr


class stat(SimProcedure):
    IS_SYSCALL = True

    def run(self, file_path, stat_buf):
        # NOTE: make everything symbolic now
        stat_t(stat_buf).store_all(self)
        return errno_success(self)


class lstat(SimProcedure):
    IS_SYSCALL = True

    def run(self, file_path, stat_buf):
        ret_expr = self.inline_call(stat, file_path, stat_buf).ret_expr
        return ret_expr


class fstat(SimProcedure):
    IS_SYSCALL = True

    def run(self, fd, stat_buf):
        # NOTE: since file_path doesn't matter
        return self.inline_call(stat, fd, stat_buf).ret_expr


class fstatat(SimProcedure):
    IS_SYSCALL = True

    def run(self, dirfd, pathname, stat_buf, flags):
        return self.inline_call(stat, pathname, stat_buf).ret_expr


class newfstatat(SimProcedure):
    IS_SYSCALL = True

    def run(self, dirfd, pathname, stat_buf, flags):
        return self.inline_call(stat, pathname, stat_buf).ret_expr


class fcntl(SimProcedure):
    ARGS_MISMATCH = True
    IS_SYSCALL = True
    def run(self, fd, cmd):
        return self.state.se.Unconstrained('fcntl', 32, uninitialized=False)


class fadvise64(SimProcedure):
    IS_SYSCALL = True
    def run(self, fd, offset, len, advise):
        return errno_success(self)


class statfs(SimProcedure):
    IS_SYSCALL = True
    
    def run(self, path, statfs_buf):
        statfs_t(statfs_buf).store_all(self)
        return errno_success(self)
        

class fstatfs(SimProcedure):
    IS_SYSCALL = True

    def run(self, fd, stat_buf):
        return self.inline_call(statfs, fd, stat_buf).ret_expr


class dup(SimProcedure):
    IS_SYSCALL = True

    def run(self, oldfd):
        return self.state.se.Unconstrained('dup', 32, uninitialized=False)


class dup2(SimProcedure):
    IS_SYSCALL = True

    def run(self, oldfd, newfd):
        return self.state.se.Unconstrained('dup2', 32, uninitialized=False)


class dup3(SimProcedure):
    IS_SYSCALL = True

    def run(self, oldfd, newfd, flags):
        return self.state.se.Unconstrained('dup3', 32, uninitialized=False)


