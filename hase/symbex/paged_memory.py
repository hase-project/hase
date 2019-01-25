import bisect
from typing import Any, Dict, List, Optional, Tuple, Union, Set


class PagedMemory:
    PAGE_SIZE = 0x1000
    ACCESS_EXECUTE = 0x1
    ACCESS_WRITE = 0x2
    ACCESS_READ = 0x4

    def __init__(self, memory: Any, pages: Dict[int, Dict[int, Any]] = dict()) -> None:
        self._pages = pages
        self._cowed = set()  # type: Set[int]
        self.memory = memory

    def _get_index_offset(self, addr: int) -> Tuple[int, int]:
        index = addr // self.PAGE_SIZE
        offset = addr % self.PAGE_SIZE
        return index, offset

    def __getitem__(self, addr: int) -> Optional[Any]:
        index, offset = self._get_index_offset(addr)

        if index not in self._pages:
            return None

        page = self._pages[index]

        if offset not in page:
            return None

        return page[offset]

    def __setitem__(self, addr: int, value: Any) -> None:
        index, offset = self._get_index_offset(addr)

        if index not in self._pages:
            page = dict()  # type: Any
            self._cowed.add(index)
            self._pages[index] = page
        else:
            page = self._pages[index]
            if index not in self._cowed:
                page = dict(page)
                self._pages[index] = page
                self._cowed.add(index)

        page[offset] = value

    def __len__(self) -> int:
        count = 0
        for p in self._pages:
            count += len(self._pages[p])
        return count

    def __contains__(self, addr: int) -> bool:
        if len(self._pages) == 0:
            return False
        indexes = sorted(self._pages.keys())
        aligned_addr = addr // self.PAGE_SIZE
        idx = bisect.bisect_left(indexes, aligned_addr)
        return len(indexes) > idx and indexes[idx] == aligned_addr

    def find(self, start: int, end: int) -> List[Any]:
        values = []  # type: List[Any]

        range_len = end - start
        if range_len >= 1024:
            indexes = sorted(self._pages.keys())
            min_index = start // self.PAGE_SIZE
            max_index = end // self.PAGE_SIZE
            offset = start % self.PAGE_SIZE

            pos = bisect.bisect_left(indexes, min_index)

            while pos < len(indexes) and indexes[pos] <= max_index:
                index = indexes[pos]
                if index in self._pages:
                    page = self._pages[index]
                    while offset < self.PAGE_SIZE:
                        if offset in page:
                            v = page[offset]
                            if type(v) in (list,):
                                for vv in v:
                                    assert type(vv) not in (list,)
                                    values.append(vv)
                            else:
                                values.append(v)

                        offset += 1
                        if index * self.PAGE_SIZE + offset > end:
                            return values
                offset = 0
                pos += 1
        else:
            addr = start
            index, offset = self._get_index_offset(addr)
            while addr <= end:
                if index not in self._pages:
                    addr += self.PAGE_SIZE - offset
                    offset = 0
                    index += 1
                    continue

                if offset in self._pages[index]:
                    v = self._pages[index][offset]
                    if type(v) in (list,):
                        for vv in v:
                            assert type(vv) not in (list,)
                            values.append(vv)
                    else:
                        values.append(v)

                addr += 1
                offset += 1
                if offset >= self.PAGE_SIZE:
                    offset = 0
                    index += 1

        return values

    def copy(self, memory: Any) -> "PagedMemory":
        return PagedMemory(pages=dict(self._pages), memory=memory)
