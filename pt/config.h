#pragma once

#include <Python.h>

#include "mmap.h"

#include <string>
#include <vector>

#include <intel-pt.h>
#include <libipt-sb.h>

namespace hase::pt {
typedef struct {
  const char *filename;
  int offset;
  int size;
  int vaddr;
} SharedObject;

typedef struct {
  struct pt_config config;
  struct pt_sb_pevent_config peventConfig;
  std::vector<const char *> perfEventFilenames;
  std::vector<SharedObject> sharedObjects;
  PyObject *switchCallback;
  Mmap trace;
} Config;

std::optional<Config> getConfig(PyObject *args, PyObject *kwdict);
} // namespace hase::pt
