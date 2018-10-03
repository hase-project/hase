#pragma once

#include <Python.h>
#include <memory>

namespace hase::pt {

struct PyObjectDeleter {
  void operator()(PyObject *const obj) { Py_DECREF(obj); }
};
typedef std::unique_ptr<PyObject, PyObjectDeleter> PyObjPtr;

} // namespace hase::pt
