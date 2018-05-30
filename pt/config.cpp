#include <Python.h>

#include "config.h"

#include <fcntl.h>
#include <intel-pt.h>
#include <libipt-sb.h>
#include <unistd.h>

namespace hase::pt {
#if PY_MAJOR_VERSION >= 3
static const char *checkNullByte(const char *str, const Py_ssize_t size) {
  for (Py_ssize_t i = 0; i < size; i++) {
    if (str[0] == '\0') {
      PyErr_SetString(PyExc_TypeError,
                      "null bytes are not allowed in filenames");
      return nullptr;
    }
  }
  return str;
}
#endif

static std::optional<const char *> getFilename(PyObject *pyFilename) {
  const char *str = nullptr;
  if (PyString_Check(pyFilename)) {
    str = PyString_AsString(pyFilename);
    if (!str) {
      return {};
    }
#if PY_MAJOR_VERSION >= 3
  } else if (PyUnicode_Check(pyFilename)) {
    Py_ssize_t size;
    char *utf8 = PyUnicode_AsUTF8AndSize(pyFilename, &size);
    str = checkNullByte(utf8, size);
    if (!str) {
      return {};
    }
#endif
  } else {
    PyErr_SetString(
        PyExc_TypeError,
        "expected bytes or unicode types as argument for filenames");
    return {};
  }
  return str;
}

static std::optional<std::vector<const char *>>
getPerfEventFilenames(PyObject *pyList) {
  std::vector<const char *> perfEventFilenames;
  perfEventFilenames.reserve(PyList_GET_SIZE(pyList));

  for (Py_ssize_t i = 0; i < PyList_GET_SIZE(pyList); i++) {
    auto item = PyList_GET_ITEM(pyList, i);
    auto filename = getFilename(item);
    if (!filename) {
      return {};
    }

    perfEventFilenames.push_back(*filename);
  }

  return perfEventFilenames;
}

static std::optional<std::vector<SharedObject>>
getSharedObjects(PyObject *pyList) {
  if (!PyList_Check(pyList)) {
    PyErr_SetString(PyExc_TypeError,
                    "shared_objects argument must of type List");
    return {};
  }

  std::vector<SharedObject> sharedObjects;
  sharedObjects.reserve(PyList_GET_SIZE(pyList));

  for (Py_ssize_t i = 0; i < PyList_GET_SIZE(pyList); i++) {
    auto item = PyList_GET_ITEM(pyList, i);

    if (!PyTuple_Check(item)) {
      PyErr_Format(
          PyExc_TypeError,
          "element at position %ld in shared_objects argument is not a tuple",
          i);
      return {};
    }

    if (PyTuple_GET_SIZE(item) != 4) {
      PyErr_Format(PyExc_TypeError,
                   "element at position %ld in shared_objects argument does "
                   "not contain 4 elements.",
                   i);
      return {};
    }

    auto filename = getFilename(PyTuple_GET_ITEM(item, 0));
    if (!filename) {
      return {};
    }

    auto offset =
        static_cast<int>(PyLong_AsUnsignedLong(PyTuple_GET_ITEM(item, 1)));
    if (PyErr_Occurred()) {
      PyErr_Format(PyExc_TypeError,
                   "second field in tuple of %ld. element in shared_objects "
                   "argument is not a long",
                   i);
      return {};
    }

    auto size =
        static_cast<int>(PyLong_AsUnsignedLong(PyTuple_GET_ITEM(item, 2)));
    if (PyErr_Occurred()) {
      PyErr_Format(PyExc_TypeError,
                   "third field in tuple of %ld. element in shared_objects "
                   "argument is not a long",
                   i);
      return {};
    }

    auto vaddr =
        static_cast<int>(PyLong_AsUnsignedLong(PyTuple_GET_ITEM(item, 3)));
    if (PyErr_Occurred()) {
      PyErr_Format(PyExc_TypeError,
                   "forth field in tuple of %ld. element in shared_objects "
                   "argument is not a long",
                   i);
      return {};
    }

    sharedObjects[i] = SharedObject{*filename, offset, size, vaddr};
  }

  return sharedObjects;
}

#define PAGE_ALIGN_DOWN(x) (((size_t)(x)) & ~((size_t)sysconf(_SC_PAGESIZE)-1)

std::optional<Config> getConfig(PyObject *args, PyObject *kwdict) {
  struct pt_config config;
  pt_config_init(&config);

  config.flags.variant.block.end_on_call = 1;
  config.flags.variant.block.end_on_jump = 1;

  config.cpu.vendor = pcv_intel;
  config.cpu.family = 0;
  config.cpu.model = 0;
  config.cpu.stepping = 0;
  config.cpuid_0x15_eax = 0;
  config.cpuid_0x15_ebx = 0;
  config.mtc_freq = 2;
  // trace buffer
  config.begin = nullptr;
  config.end = nullptr;

  struct pt_sb_pevent_config pevent = {};
  pevent.size = sizeof(pevent);
  pevent.kernel_start = 0xfffff00000000000;
  pevent.sample_type = 0;
  pevent.time_zero = 0;
  pevent.time_shift = 0;
  pevent.tsc_offset = 0;
  pevent.time_mult = 1;
  pevent.primary = 1;
  pevent.filename = "";
  pevent.sysroot = "";
  pevent.vdso_x64 = "";

  const char *kwlist[] = {
      "trace_filename",      //
      "cpu_family",          //
      "cpu_model",           //
      "cpu_stepping",        //
      "cpuid_0x15_eax",      //
      "cpuid_0x15_ebx",      //
      "sample_type",         //
      "time_zero",           //
      "time_shift",          //
      "time_mult",           //
      "sysroot",             //
      "vdso_x64",            //
      "perf_events_per_cpu", //
      "switch_callback",     //
      nullptr,
  };

  const char *types = "s"  // trace_filename
                      "h"  // cpu_family
                      "b"  // cpu_model
                      "b"  // cpu_stepping
                      "I"  // cpuid_0x15_eax
                      "I"  // cpuid_0x15_ebx
                      "K"  // sample_type
                      "K"  // time_zero
                      "H"  // time_shift
                      "I"  // time_mult
                      "s"  // sysroot
                      "s"  // vdso_x64
                      "O!" // perf_events_per_cpu
                      "O"  // switch_callback
                      ":decode";

  unsigned int cpuid_0x15_eax = 0, cpuid_0x15_ebx = 0;
  const char *traceFilename = nullptr;
  PyObject *pyPerfEventFilenames = nullptr;
  PyObject *pySharedObjects = nullptr;
  PyObject *switchCallback = nullptr;

  if (!PyArg_ParseTupleAndKeywords(args, kwdict, types,
                                   const_cast<char **>(kwlist),         //
                                   &traceFilename,                      //
                                   &config.cpu.family,                  //
                                   &config.cpu.model,                   //
                                   &config.cpu.stepping,                //
                                   &cpuid_0x15_eax,                     //
                                   &cpuid_0x15_ebx,                     //
                                   &pevent.sample_type,                 //
                                   &pevent.time_zero,                   //
                                   &pevent.time_shift,                  //
                                   &pevent.time_mult,                   //
                                   &pevent.sysroot,                     //
                                   &pevent.vdso_x64,                    //
                                   &PyList_Type, &pyPerfEventFilenames, //
                                   &switchCallback)) {                  //
    return {};
  }

  config.cpuid_0x15_eax = (uint32_t)cpuid_0x15_eax;
  config.cpuid_0x15_ebx = (uint32_t)cpuid_0x15_ebx;

  if (!PyCallable_Check(switchCallback)) {
    PyErr_SetString(PyExc_TypeError, "switch_callback must be callable");
    return {};
  }

  auto perfEventFilenames = getPerfEventFilenames(pyPerfEventFilenames);
  if (!perfEventFilenames) {
    return {};
  }

  // auto sharedObjects = getSharedObjects(pySharedObjects);
  // if (!sharedObjects) {
  //  return {};
  //}

  int fd = open(traceFilename, O_RDONLY);
  if (fd < 0) {
    PyErr_SetFromErrnoWithFilename(PyExc_OSError, traceFilename);
    return {};
  }

  struct stat sb;
  int r = fstat(fd, &sb);
  if (r < 0) {
    close(fd);
    PyErr_Format(PyExc_OSError, "failed to fstat %s: %s", traceFilename,
                 strerror(errno));
    return {};
  }

  auto trace = Mmap::create(nullptr, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (!trace) {
    PyErr_Format(PyExc_OSError, "failed to mmap file %s: %s", traceFilename,
                 strerror(errno));
    return {};
  }

  config.begin = trace->begin();
  config.end = trace->end();

  Config c = {};
  c.trace = *std::move(trace);
  c.config = config;
  c.peventConfig = pevent;
  c.perfEventFilenames = *perfEventFilenames;
  // c.sharedObjects = *sharedObjects;
  c.switchCallback = switchCallback;

  return c;
}
} // namespace hase::pt
