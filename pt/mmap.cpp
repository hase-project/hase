#include "mmap.h"

#include <fcntl.h>
#include <optional>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

Mmap::Mmap(Mmap &&old) { *this = std::move(old); }

Mmap &Mmap::operator=(Mmap &&old) {
  if (this != &old) {
    this->fd = old.fd;
    this->data = old.data;
    this->length = old.length;

    old.fd = -1;
    old.data = (uint8_t *)MAP_FAILED;
    old.length = 0;
  }

  return *this;
}

Mmap::~Mmap() {
  if (fd != -1) {
    close(fd);
  }

  if (data != MAP_FAILED && length != 0) {
    munmap(data, length);
  }
}

std::optional<Mmap> Mmap::create(void *addr, size_t length, int prot, int flags,
                                 int fd, off_t offset) {
  Mmap m;
  m.fd = fd;
  m.length = -1;

  auto data = ::mmap(nullptr, length, prot, flags, fd, offset);
  if (data == MAP_FAILED) {
    return {};
  }

  m.data = static_cast<uint8_t *>(data);
  m.length = length;

  return std::move(m);
}
