untree_next_id = 1

class Untree(object):

    _round = 0
    _log   = None

    def __init__(self, items=[], log=None, trace=True):
        self._list = items
        self._log  = log

        global untree_next_id
        self._id = untree_next_id
        untree_next_id += 1

        if trace:
            self._do_log(['n', str(self._id)])

    @classmethod
    def set_log(cls, log):
        assert Untree._log is None
        Untree._log = log

    @classmethod
    def new_round(cls):
        Untree._round += 1
        if Untree._log is not None:
            Untree._log.append(['r', str(Untree._round)])

    def _do_log(self, item):
        log = self._log   if self._log   is not None else  \
              Untree._log if Untree._log is not None else  \
              None
        if log is not None:
            log.append(item)

    def search(self, a, b):

        self._do_log(['s', str(self._id), str(a), str(b)])

        res = []
        for e in self._list:
            if self._intersect(a, b, e.begin, e.end):
                res.append(e)

        return set(res)

    def update_item(self, e, data):

        self._do_log(['u', str(self._id), str(id(e.data)), str(id(data))])

        new_e = UntreeItem(e.begin, e.end, data, e.index)
        self._list[e.index] = new_e

    def copy(self):

        r = Untree(self._list[:], log=(self._log[:] if self._log is not None else None), trace=False)

        self._do_log(['c', str(self._id), str(r._id)])
        if Untree._log is None: r._do_log(['c', str(self._id), str(r._id)])

        return r

    def add(self, begin, end, data):

        self._do_log(['a', str(self._id), str(begin), str(end), str(id(data))])

        e = UntreeItem(begin, end, data, len(self._list))
        self._list.append(e)

    def _intersect(self, a_min, a_max, b_min, b_max):
        return min(a_max, b_max) - max(a_min, b_min) > 0

    def get_stats(self):
        return None

    @staticmethod
    def print_stats(cls, data):
        return


class UntreeItem(object):
    __slots__ = ('begin', 'end', 'data', 'index')

    def __init__(self, begin, end, data, index):
        self.begin = begin
        self.end = end
        self.data = data
        self.index = index
