#include <Python.h>

#include "config.h"

#include <fcntl.h>
#include <intel-pt.h>
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
  if (PyBytes_Check(pyFilename)) {
    str = PyBytes_AsString(pyFilename);
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
        PyLong_AsUnsignedLong(PyTuple_GET_ITEM(item, 1));
    if (PyErr_Occurred()) {
      PyErr_Format(PyExc_TypeError,
                   "second field in tuple of %ld. element in shared_objects "
                   "argument is not a long",
                   i);
      return {};
    }

    auto size =
        PyLong_AsUnsignedLong(PyTuple_GET_ITEM(item, 2));
    if (PyErr_Occurred()) {
      PyErr_Format(PyExc_TypeError,
                   "third field in tuple of %ld. element in shared_objects "
                   "argument is not a long",
                   i);
      return {};
    }

    auto vaddr =
        PyLong_AsUnsignedLong(PyTuple_GET_ITEM(item, 3));
    if (PyErr_Occurred()) {
      PyErr_Format(PyExc_TypeError,
                   "forth field in tuple of %ld. element in shared_objects "
                   "argument is not a long",
                   i);
      return {};
    }

    sharedObjects.push_back(SharedObject{*filename, offset, size, vaddr});
  }

  return sharedObjects;
}

#define PAGE_ALIGN_DOWN(x) (((size_t)(x)) & ~((size_t)sysconf(_SC_PAGESIZE)-1)

std::optional<Config> getConfig(PyObject *args, PyObject *kwdict) {
  uint64_t timeZero;
  uint16_t timeShift;
  uint32_t timeMult;

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

  const char *kwlist[] = {
      "trace_path", //
      "cpu_family",     //
      "cpu_model",      //
      "cpu_stepping",   //
      "cpuid_0x15_eax", //
      "cpuid_0x15_ebx", //
      "time_zero",      //
      "time_shift",     //
      "time_mult",      //
      "shared_objects", //
      nullptr,
  };

  const char *types = "s"  // trace_path
                      "h"  // cpu_family
                      "b"  // cpu_model
                      "b"  // cpu_stepping
                      "I"  // cpuid_0x15_eax
                      "I"  // cpuid_0x15_ebx
                      "K"  // time_zero
                      "H"  // time_shift
                      "I"  // time_mult
                      "O!" // shared_objects
                      ":decode";

  unsigned int cpuid_0x15_eax = 0, cpuid_0x15_ebx = 0;
  const char *tracePath = nullptr;
  PyObject *pySharedObjects = nullptr;

  if (!PyArg_ParseTupleAndKeywords(args, kwdict, types,
                                   const_cast<char **>(kwlist), //
                                   &tracePath,                  //
                                   &config.cpu.family,          //
                                   &config.cpu.model,           //
                                   &config.cpu.stepping,        //
                                   &cpuid_0x15_eax,             //
                                   &cpuid_0x15_ebx,             //
                                   &timeZero,                   //
                                   &timeShift,                  //
                                   &timeMult,                   //
                                   &PyList_Type,                //
                                   &pySharedObjects)) {         //
    return {};
  }

  config.cpuid_0x15_eax = (uint32_t)cpuid_0x15_eax;
  config.cpuid_0x15_ebx = (uint32_t)cpuid_0x15_ebx;

  auto sharedObjects = getSharedObjects(pySharedObjects);
  if (!sharedObjects) {
    return {};
  }

  int fd = open(tracePath, O_RDONLY);
  if (fd < 0) {
    PyErr_SetFromErrnoWithFilename(PyExc_OSError, tracePath);
    return {};
  }

  struct stat sb;
  int r = fstat(fd, &sb);
  if (r < 0) {
    close(fd);
    PyErr_Format(PyExc_OSError, "failed to fstat %s: %s", tracePath,
                 strerror(errno));
    return {};
  }

  auto trace = Mmap::create(nullptr, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (!trace) {
    PyErr_Format(PyExc_OSError, "failed to mmap file %s: %s", tracePath,
                 strerror(errno));
    return {};
  }

  config.begin = trace->begin();
  config.end = trace->end();

  Config c = {
      TscConverter(timeZero, timeShift, timeMult), // tscConverter
      config,                                      // config
      *sharedObjects,                              // sharedObjects
      *std::move(trace),                           // trace
  };

  return std::move(c);
}
} // namespace hase::pt
