#!/usr/bin/python

import sys
from .parser import parser 
from .pitree import pitree 


class runner(parser):

    def __init__(self):
        parser.__init__(self)
        self.pitrees = dict()

    def _do_copy(self, parms):
        parser._do_copy(self, parms)
        t = self.pitrees[parms[0]]
        self.pitrees[parms[1]] = t.copy()

    def _do_add(self, parms):
        parser._do_add(self, parms)
        t = self.pitrees[parms[0]]
        t.add(parms[1], parms[2], parms[3])

    def _do_update(self, parms):
        parser._do_update(self, parms)
        t = self.pitrees[parms[0]]
        i_pitree = None
        for i in t.search(0, sys.maxsize):
            if i.data == parms[1]:
                assert i_pitree == None
                i_pitree = i
        t.update_item(i_pitree, parms[2])

    def _do_new(self, parms):
        parser._do_new(self, parms)
        t = pitree()
        self.pitrees[parms[0]] = t

    def _do_search(self, parms):
        parser._do_search(self, parms)
        t = self.pitrees[parms[0]]
        return runner._tree2set(t, parms[1], parms[2])

    @classmethod
    def _tree2set(cls, t, begin=0, end=sys.maxsize):
        s = set()
        for i in t.search(begin, end):
            s.add((i.begin, i.end, i.data))
        return s

# test
def main(args):
     print("opening log file %s" % args[0])
     t = runner()
     t.run(args[0])
     return 0

if __name__ == "__main__":
   main(sys.argv[1:])
