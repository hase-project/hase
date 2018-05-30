#include <Python.h>

#include "decode.h"
#include "instruction.h"
#include "ptr.h"

namespace hase::pt {

#define _public_ __attribute__((visibility("default")))

#if PY_MAJOR_VERSION >= 3
#define MOD_INIT(name) PyMODINIT_FUNC _public_ PyInit_##name(void)
#define MOD_DEF(ob, name, doc, methods)                                        \
  static struct PyModuleDef moduledef = {                                      \
      PyModuleDef_HEAD_INIT, name, doc, -1, methods,                           \
  };                                                                           \
  ob = PyModule_Create(&moduledef);
#define MOD_SUCCESS_VAL(val) val
#else
#define MOD_INIT(name) PyMODINIT_FUNC _public_ init##name(void)
#define MOD_DEF(ob, name, doc, methods) ob = Py_InitModule3(name, methods, doc);
#define MOD_SUCCESS_VAL(val)
#endif

static PyMethodDef PtMethods[] = {{"decode", (PyCFunction)decode,
                                   METH_VARARGS | METH_KEYWORDS,
                                   "decode processor trace"},
                                  {NULL, NULL, 0, NULL}};

PyObjPtr PtError = nullptr;
PyObjPtr Instruction = nullptr;

MOD_INIT(_pt) {
  PyObject *m;
  MOD_DEF(m, "_pt", "Processor-trace decoder bindings", PtMethods);
  PyObjPtr module(m);
  if (!module) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  PyObjPtr errModule(PyImport_ImportModule("hase.errors"));
  if (!errModule) {
    return MOD_SUCCESS_VAL(nullptr);
  }
  PyObjPtr error(PyObject_GetAttrString(errModule.get(), "PtError"));
  PtError = std::move(error);
  if (!PtError) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  PyObjPtr instructionModule(PyImport_ImportModule("hase.instruction"));
  if (!instructionModule) {
    return MOD_SUCCESS_VAL(nullptr);
  }
  PyObjPtr instruction(
      PyObject_GetAttrString(instructionModule.get(), "Instruction"));
  Instruction = std::move(instruction);
  if (!Instruction) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  module.release();
  return MOD_SUCCESS_VAL(m);
}
} // namespace hase::pt
