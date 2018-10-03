#pragma once

#include <Python.h>

#include "mmap.h"
#include "pt.h"
#include "tsc.h"

#include <string>
#include <vector>

#include <intel-pt.h>

namespace hase::pt {
typedef struct {
  const char *filename;
  uint64_t offset;
  uint64_t size;
  uint64_t vaddr;
} SharedObject;

typedef struct {
  TscConverter tscConverter;
  struct pt_config config;
  std::vector<SharedObject> sharedObjects;
  Mmap trace;
} Config;

std::optional<Config> getConfig(PyObject *args, PyObject *kwdict);
} // namespace hase::pt
