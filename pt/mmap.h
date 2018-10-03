#pragma once

#include <optional>
#include <stdint.h>
#include <sys/mman.h>
#include <utility>

class Mmap {
public:
  static std::optional<Mmap> create(void *addr, size_t length, int prot,
                                    int flags, int fd, off_t offset);

  uint8_t *begin() { return data; }
  uint8_t *end() { return data + length; }
  Mmap() = default;
  ~Mmap();
  Mmap(Mmap &&old);
  Mmap &operator=(Mmap &&old);

private:
  int fd = -1;
  uint8_t *data = static_cast<uint8_t *>(MAP_FAILED);
  size_t length = 0;
};
