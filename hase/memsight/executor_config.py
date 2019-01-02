import imp
import sys
import os
import exceptions

def get_target_addrs(fname):

    try:
        config = imp.load_source(os.path.basename(fname), fname + ".py")
    except exceptions.IOError:
        print("config python script related to binary file is missing")
        print(("Create " + str(fname) + ".py with the following functions:"))
        print("\t        start()    => int")
        print("\t        avoid()    => [int, ...]")
        print("\t          end()    => [int, ...]")
        print("\tdo_start(state)    => o")
        print("\t  do_end(state, o, pg) => None")
        sys.exit(1)

    start = config.start()
    avoid = config.avoid()
    end = config.end()

    return start, avoid, end, config