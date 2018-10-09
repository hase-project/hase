#include <Python.h>

#include "decode.h"
#include "events.h"
#include "ptr.h"

namespace hase::pt {

#define _public_ __attribute__((visibility("default")))

static PyMethodDef PtMethods[] = {{"decode", (PyCFunction)decode,
                                   METH_VARARGS | METH_KEYWORDS,
                                   "decode processor trace"},
                                  {nullptr, nullptr, 0, nullptr}};

static struct PyModuleDef _PtModule = {
    PyModuleDef_HEAD_INIT, "_pt", "Processor-trace decoder bindings", -1, PtMethods,
};

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

extern "C" _public_ PyObject *PyInit__pt(void) {
  PyObjPtr module(PyModule_Create(&_PtModule));
  if (!module) {
    return nullptr;
  }

  PyObjPtr errModule(PyImport_ImportModule("hase.errors"));
  if (!errModule) {
    return nullptr;
  }

  if (!getAttr(errModule, "PtError", PtError)) {
    return nullptr;
  }

  PyObjPtr ptModule(PyImport_ImportModule("hase.pt.events"));
  if (!ptModule) {
    return nullptr;
  }

  if (!getAttr(ptModule, "Instruction", Instruction)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "InstructionClass", InstructionClass)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "EnableEvent", EnableEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "DisableEvent", DisableEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "AsyncDisableEvent", AsyncDisableEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "AsyncBranchEvent", AsyncBranchEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "PagingEvent", PagingEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "AsyncPagingEvent", AsyncPagingEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "OverflowEvent", OverflowEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "ExecModeEvent", ExecModeEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "TsxEvent", TsxEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "StopEvent", StopEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "VmcsEvent", VmcsEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "AsyncVmcsEvent", AsyncVmcsEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "ExstopEvent", ExstopEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "MwaitEvent", MwaitEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "PwreEvent", PwreEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "PwrxEvent", PwrxEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "PtWriteEvent", PtWriteEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "TickEvent", TickEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "CbrEvent", CbrEvent)) {
    return nullptr;
  }

  if (!getAttr(ptModule, "MntEvent", MntEvent)) {
    return nullptr;
  }

  return module.release();
}
} // namespace hase::pt
