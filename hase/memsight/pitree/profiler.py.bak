#!/usr/bin/python

import sys
from .runner import runner 
from pympler import asizeof, tracker
from .pitree import pitree 

class profiler(runner):

    def __init__(self):
        runner.__init__(self)

    def print_report(self):
        print("----------------")
        print("selecting trees created at round %d..." % self.round)
        l   = []
        pit = set()
        for tid in self.pitrees:
            if self.lookup[tid] == self.round:
                t = self.pitrees[tid]
                s = t.get_stats()
                print("%d: %s" % (tid, str(s)))
                l.append(s)
                pit.add(t)
        print("%d tree(s) selected." % len(l))
        print("----------------")
        pitree.print_stats(l)
        print("----------------")
        print("Total memory used by pitrees in the frontier: %u" % asizeof.asizeof(pit))

# test
def main(args):
     print("opening log file %s" % args[0])
     t = profiler()
     t.run(args[0])
     t.print_report()
     return 0

if __name__ == "__main__":
   main(sys.argv[1:])
