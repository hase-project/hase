#!/usr/bin/python

import sys
from .runner import runner 
from .untree import Untree


class tester(runner):

    def __init__(self):
        runner.__init__(self)
        self.untrees = dict()

    def _do_copy(self, parms):
        runner._do_copy(self, parms)
        t = self.untrees[parms[0]]
        self.untrees[parms[1]] = t.copy()
        self._check_trees(parms[0])
        self._check_trees(parms[1])

    def _do_add(self, parms):
        runner._do_add(self, parms)
        t = self.untrees[parms[0]]
        t.add(parms[1], parms[2], parms[3])
        self._check_trees(parms[0])

    def _do_update(self, parms):
        runner._do_update(self, parms)
        t = self.untrees[parms[0]]
        i_untree = None
        for i in t.search(0, sys.maxsize):
            if i.data == parms[1]:
                assert i_untree == None
                i_untree = i
        t.update_item(i_untree, parms[2])
        self._check_trees(parms[0])

    def _do_new(self, parms):
        runner._do_new(self, parms)
        t = Untree()
        self.untrees[parms[0]] = t
        self._check_trees(parms[0])

    def _do_search(self, parms):
        runner._do_search(self, parms)
        pit = self.pitrees[parms[0]]
        unt = self.untrees[parms[0]]
        s_pitree = runner._tree2set(pit, parms[1], parms[2])
        s_untree = runner._tree2set(unt, parms[1], parms[2])
        if not tester._check_sets(s_pitree, s_untree, "### search(%d, %d) error: " % (parms[1], parms[2])):
            self._dump_tree(self.untrees[parms[0]], parms[0])
            sys.exit(1)
        self._check_trees(parms[0])

    def _dump_tree(self, t, tree_id):
        f = open("dump.log", "w") 
        f.write("n,%d\n" % tree_id)
        for i in t.search(0, sys.maxsize):
            f.write("a,%d,%d,%d,%d\n" % (tree_id, i.begin, i.end, i.data))
        f.close()

    def _check_trees(self, tree_id):
        pit = self.pitrees[tree_id]
        unt = self.untrees[tree_id]
        s_pitree = runner._tree2set(pit)
        s_untree = runner._tree2set(unt)
        if not tester._check_sets(s_pitree, s_untree, "### misaligned trees error"):
            self._dump_tree(self.untrees[tree_id], tree_id)
            sys.exit(1)

    @classmethod
    def _check_sets(cls, s_pitree, s_untree, msg):
        if s_pitree != s_untree:
            print(msg)
            print("    s_pitree - s_untree = " + str(s_pitree - s_untree))
            print("    s_untree - s_pitree = " + str(s_untree - s_pitree))
            return False
        return True

# test
def main(args):
     print("opening log file %s" % args[0])
     t = tester()
     t.run(args[0])
     return 0

if __name__ == "__main__":
   main(sys.argv[1:])
