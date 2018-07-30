#include <Python.h>

#include "decode.h"
#include "events.h"
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
PyObjPtr InstructionClass = nullptr;
PyObjPtr EnableEvent = nullptr;
PyObjPtr DisableEvent = nullptr;
PyObjPtr AsyncDisableEvent = nullptr;
PyObjPtr AsyncBranchEvent = nullptr;
PyObjPtr PagingEvent = nullptr;
PyObjPtr AsyncPagingEvent = nullptr;
PyObjPtr OverflowEvent = nullptr;
PyObjPtr ExecModeEvent = nullptr;
PyObjPtr TsxEvent = nullptr;
PyObjPtr StopEvent = nullptr;
PyObjPtr VmcsEvent = nullptr;
PyObjPtr AsyncVmcsEvent = nullptr;
PyObjPtr ExstopEvent = nullptr;
PyObjPtr MwaitEvent = nullptr;
PyObjPtr PwreEvent = nullptr;
PyObjPtr PwrxEvent = nullptr;
PyObjPtr PtWriteEvent = nullptr;
PyObjPtr TickEvent = nullptr;
PyObjPtr CbrEvent = nullptr;
PyObjPtr MntEvent = nullptr;

bool getAttr(PyObjPtr &source, const char *name, PyObjPtr &target) {
  auto sourcePtr = source.get();
  assert(sourcePtr);
  PyObjPtr obj(PyObject_GetAttrString(sourcePtr, name));
  target = std::move(obj);
  return !!target;
}

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

  if (!getAttr(errModule, "PtError", PtError)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  PyObjPtr ptModule(PyImport_ImportModule("hase.pt.events"));
  if (!ptModule) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "Instruction", Instruction)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "InstructionClass", InstructionClass)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "EnableEvent", EnableEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "DisableEvent", DisableEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "AsyncDisableEvent", AsyncDisableEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "AsyncBranchEvent", AsyncBranchEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "PagingEvent", PagingEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "AsyncPagingEvent", AsyncPagingEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "OverflowEvent", OverflowEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "ExecModeEvent", ExecModeEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "TsxEvent", TsxEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "StopEvent", StopEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "VmcsEvent", VmcsEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "AsyncVmcsEvent", AsyncVmcsEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "ExstopEvent", ExstopEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "MwaitEvent", MwaitEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "PwreEvent", PwreEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "PwrxEvent", PwrxEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "PtWriteEvent", PtWriteEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "TickEvent", TickEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "CbrEvent", CbrEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  if (!getAttr(ptModule, "MntEvent", MntEvent)) {
    return MOD_SUCCESS_VAL(nullptr);
  }

  module.release();
  return MOD_SUCCESS_VAL(m);
}
} // namespace hase::pt
