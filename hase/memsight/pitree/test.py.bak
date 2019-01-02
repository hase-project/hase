#!/usr/bin/python

import sys 
from .pitree import pitree 
from pympler import asizeof, tracker

# test
def main(args):
    tr = tracker.SummaryTracker()

    t = pitree()
    t.add(2413, 2414, "zero")
    t.add(2400, 3290, "one")
    t.add(1250, 2913, "two")
    t.add(2999, 4601, "three")
    t.add(1639, 3007, "four")
    t.add(1639, 3007, "four'")

    print("t")
    for i in t.search(0,sys.maxsize): print(i)

    print("update t:")
    for i in t.search(1250, 1251):
        i = t.update_item(i, i.data + "---")
        print(i.begin, " ", i.end, " ", i.data)

    print("r = copy of t")
    r = t.copy()

    print("update r:")
    for i in r.search(123, 2400):
        i = r.update_item(i, i.data + "*")
        print(i.begin, " ", i.end, " ", i.data)

    print("update again t:")
    for i in t.search(4600, 4601):
        i = t.update_item(i, i.data + "###")
        print(i.begin, " ", i.end, " ", i.data)

    print("t")
    for i in t.search(0,sys.maxsize): print(i)

    print("r")
    for i in r.search(0,sys.maxsize): print(i)

    print("s = copy of r")
    s = r.copy()

    print("add to s")
    s.add(113, 1784, "five")
    s.add(114, 1784, "six")
    s.add(114, 1784, "seven")

    print("t")
    for i in t.search(0,sys.maxsize): print(i)

    print("r")
    for i in r.search(0,sys.maxsize): print(i)

    print("s")
    for i in s.search(0,sys.maxsize): print(i)

    pitree.print_stats([t.get_stats(), r.get_stats(), s.get_stats()])

    tr.print_diff()

    return 0

if __name__ == "__main__":
   main(sys.argv[1:])

