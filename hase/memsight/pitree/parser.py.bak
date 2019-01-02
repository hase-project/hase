#!/usr/bin/python

class parser:

    def __init__(self):
        self.cnt    = 1
        self.round  = 0
        self.lookup = dict()

    def run(self, filename):
        for op in parser._read_log_file(filename):
            self._do_op(op)

    def _do_op(self, op):
        parms = [int(i) for i in op[1:]]
        if   op[0] == 'c': self._do_copy(parms)
        elif op[0] == 'a': self._do_add(parms)
        elif op[0] == 'u': self._do_update(parms)
        elif op[0] == 'n': self._do_new(parms)
        elif op[0] == 's': self._do_search(parms)
        elif op[0] == 'r': self._do_round(parms)
        else:              raise ValueError("unknown operation " + str(op[0]))
        self.cnt += 1

    def _do_round(self, parms):
        print("%d round %s" % (self.cnt, str(parms)))
        self.round = parms[0]

    def _do_copy(self, parms):
        print("%d copy %s" % (self.cnt, str(parms)))
        assert parms[0] in self.lookup
        assert parms[1] not in self.lookup
        self.lookup[parms[1]] = self.round

    def _do_add(self, parms):
        print("%d add %s" % (self.cnt, str(parms)))
        assert parms[0] in self.lookup

    def _do_update(self, parms):
        print("%d update %s" % (self.cnt, str(parms)))
        assert parms[0] in self.lookup

    def _do_new(self, parms):
        print("%d new %s" % (self.cnt, str(parms)))
        assert parms[0] not in self.lookup
        self.lookup[parms[0]] = self.round

    def _do_search(self, parms):
        print("%d search %s" % (self.cnt, str(parms)))
        assert parms[0] in self.lookup

    @classmethod
    def _read_log_file(cls, filename):
        f = open(filename, "r") 
        for line in f:
            yield line.replace("\n","").split(",")
