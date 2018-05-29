import pry
import sys
from ...path import Tempdir
from . import PerfRecord
import time

if __name__ == "__main__":
    with pry:
        with Tempdir() as t, PerfRecord() as record:
            #for i in range(1000000):
            #    sys.stderr.write(".")
            #sys.stderr.write("\n")
            time.sleep(3)
            record.write(str(t))
