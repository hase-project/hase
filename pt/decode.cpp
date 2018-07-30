#include <Python.h>

#include "decode.h"

#include <csignal>
#include <cstdarg>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "config.h"
#include "events.h"
#include "pt.h"
#include "pt_error.h"
#include "ptr.h"

namespace hase::pt {

static std::string intToHex(uint64_t i) {
  std::stringstream stream;
  stream << "0x" << std::setfill('0') << std::setw(sizeof(uint64_t) * 2)
         << std::hex << i;
  return stream.str();
}

PyObjPtr newObject(PyObjPtr &event, const char *fmt, ...) {
  va_list vargs;
  va_start(vargs, fmt);
  PyObjPtr args(Py_VaBuildValue(fmt, vargs));
  va_end(vargs);

  if (!args) {
    return nullptr;
  }

  return PyObjPtr(PyObject_CallObject(event.get(), args.get()));
}

PyObjPtr newInstruction(uint64_t ip, uint8_t size, enum pt_insn_class iclass) {
  PyObjPtr instructionClass(PyObject_CallFunction(InstructionClass.get(), (char*)("I"), (int)iclass));
  if (!instructionClass) {
      return nullptr;
  }

  return newObject(Instruction, "KBO", ip, size, instructionClass.get());
}

PyObject *newBool(bool v) {
  if (v) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
}

PyObject *newOptionalUnsignedLongLong(unsigned long long val, bool flag) {
  if (flag) {
    return PyLong_FromUnsignedLong(val);
  } else {
    Py_RETURN_NONE;
  }
}

PyObjPtr newEvent(const struct pt_event &event, uint64_t rawOffset,
                  TscConverter &converter) {
  PyObjPtr offset(PyLong_FromUnsignedLongLong(rawOffset));
  if (!offset) {
    return nullptr;
  }

  uint64_t rawTime = converter.tscToPerfTime(event.tsc);
  PyObjPtr time(newOptionalUnsignedLongLong(rawTime, event.has_tsc));
  if (!time) {
    return nullptr;
  }

  switch (event.type) {
  case ptev_enabled: {
    PyObjPtr resumed(newBool(event.variant.enabled.resumed));
    if (!resumed) {
      return nullptr;
    }

    return newObject(EnableEvent, "OOKO", offset.get(), time.get(),
                     event.variant.enabled.ip, resumed.get());
  }
  case ptev_disabled: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.disabled.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }
    return newObject(DisableEvent, "OOO", offset.get(), time.get(), ip.get());
  }
  case ptev_async_disabled: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.async_disabled.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }

    return newObject(AsyncDisableEvent, "OOOK", offset.get(), time.get(),
                     ip.get(), event.variant.async_disabled.at);
  }
  case ptev_async_branch: {
    return newObject(AsyncBranchEvent, "OOK", offset.get(), time.get(),
                     event.variant.async_branch.from);
  }
  case ptev_paging: {
    PyObjPtr nonRoot(newBool(event.variant.paging.non_root));
    if (!nonRoot) {
      return nullptr;
    }
    return newObject(PagingEvent, "OOKO", offset.get(), time.get(),
                     event.variant.paging.cr3, nonRoot.get());
  }
  case ptev_async_paging: {
    PyObjPtr nonRoot(newBool(event.variant.async_paging.non_root));
    if (!nonRoot) {
      return nullptr;
    }
    return newObject(AsyncPagingEvent, "OOKOK", offset.get(), time.get(),
                     event.variant.async_paging.ip, event.variant.paging.cr3,
                     nonRoot.get());
  }
  case ptev_overflow: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.overflow.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }
    return newObject(OverflowEvent, "OOO", offset.get(), time.get(), ip.get());
  }
  case ptev_exec_mode: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.exec_mode.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }
    return newObject(ExecModeEvent, "OOOi", offset.get(), time.get(), ip.get(),
                     event.variant.exec_mode.mode);
  }
  case ptev_tsx: {
    PyObjPtr ip(
        newOptionalUnsignedLongLong(event.variant.tsx.ip, event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }

    PyObjPtr aborted(newBool(event.variant.tsx.aborted));
    if (!aborted) {
      return nullptr;
    }

    PyObjPtr speculative(newBool(event.variant.tsx.speculative));
    if (!speculative) {
      return nullptr;
    }

    return newObject(TsxEvent, "OOOOO", offset.get(), time.get(), ip.get(),
                     aborted.get(), speculative.get());
  }
  case ptev_stop: {
    return newObject(StopEvent, "OO", offset.get(), time.get());
  }
  case ptev_vmcs: {
    return newObject(VmcsEvent, "OOK", offset.get(), time.get(),
                     event.variant.vmcs.base);
  }
  case ptev_async_vmcs: {
    return newObject(AsyncVmcsEvent, "OOKK", offset.get(), time.get(),
                     event.variant.async_vmcs.ip,
                     event.variant.async_vmcs.base);
  }
  case ptev_exstop: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.exstop.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }
    return newObject(ExstopEvent, "OOO", offset.get(), time.get(), ip.get());
  }
  case ptev_mwait: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.mwait.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }
    return newObject(MwaitEvent, "OOOii", offset.get(), time.get(), ip.get(),
                     event.variant.mwait.hints, event.variant.mwait.ext);
  }
  case ptev_pwre: {
    PyObjPtr hw(newBool(event.variant.pwre.hw));
    if (!hw) {
      return nullptr;
    }

    return newObject(PwreEvent, "OOBBO", offset.get(), time.get(),
                     event.variant.pwre.state, event.variant.pwre.sub_state,
                     hw.get());
  }
  case ptev_pwrx: {
    PyObjPtr interrupt(newBool(event.variant.pwrx.interrupt));
    if (!interrupt) {
      return nullptr;
    }

    PyObjPtr store(newBool(event.variant.pwrx.store));
    if (!store) {
      return nullptr;
    }

    PyObjPtr autonomous(newBool(event.variant.pwrx.autonomous));
    if (!autonomous) {
      return nullptr;
    }

    return newObject(PwrxEvent, "OOOOOBB", offset.get(), time.get(),
                     interrupt.get(), store.get(), autonomous.get(),
                     event.variant.pwrx.last, event.variant.pwrx.deepest);
  }
  case ptev_ptwrite: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.ptwrite.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }

    return newObject(PwreEvent, "OOOK", offset.get(), time.get(), ip.get(),
                     event.variant.ptwrite.payload);
  }
  case ptev_tick: {
    PyObjPtr ip(newOptionalUnsignedLongLong(event.variant.tick.ip,
                                            event.ip_suppressed));
    if (!ip) {
      return nullptr;
    }
    return newObject(TickEvent, "OOO", offset.get(), time.get(), ip.get());
  }
  case ptev_cbr: {
    return newObject(CbrEvent, "OOB", offset.get(), time.get(),
                     event.variant.cbr.ratio);
  }
  default: // ptev_mnt
    return newObject(CbrEvent, "OOK", offset.get(), time.get(),
                     event.variant.mnt.payload);
  }
}

class Decoder {
public:
  Decoder(PtImage image, PtInsnDecoder decoder, TscConverter tscConverter)
      : image(std::move(image)), decoder(std::move(decoder)),
        tscConverter(tscConverter) {}

  PyObjPtr diagnoseError(int errcode, struct pt_insn &insn) {
    std::string ip;
    uint64_t pos;
    ip = intToHex(insn.ip);
    int r = pt_insn_get_offset(decoder.get(), &pos);

    if (r < 0) {
      return PyObjPtr(PyErr_Format(
          PtError.get(), "synchronisation failed at offset ? and ip %s: %s",
          ip.c_str(), pt_errstr(pt_errcode(errcode))));
    }
    auto posStr = intToHex(pos);
    return PyObjPtr(PyErr_Format(
        PtError.get(), "synchronisation failed at offset %s and ip %s: %s",
        posStr.c_str(), ip.c_str(), pt_errstr(pt_errcode(errcode))));
  }

  int addSharedObject(SharedObject &obj) {
    int r = pt_image_add_file(image.get(), obj.filename, obj.offset, obj.size,
                              nullptr, obj.vaddr);
    if (r < 0) {
      PyErr_Format(PtError.get(),
                   "cannot add shared object %s to instruction image: %s",
                   obj.filename, pt_errstr(pt_errcode(r)));
      return r;
    }
    return 0;
  }

  PyObjPtr run() {
    PyObjPtr events(PyList_New(0));

    uint64_t sync = 0;

    struct pt_insn insn = {};

    for (;;) {
      int status = pt_insn_sync_forward(decoder.get());
      if (status < 0) {
        if (status == -pte_eos) {
          return events;
        }

        // Let's see if we made any progress.  If we haven't,
        // we likely never will.  Bail out.
        //
        // We intentionally report the error twice to indicate
        // that we tried to re-sync.  Maybe it even changed.
        //
        uint64_t newSync = 0;
        int r = pt_insn_get_offset(decoder.get(), &newSync);
        if (r < 0 || (newSync <= sync)) {
          return diagnoseError(status, insn);
        }

        sync = newSync;
        continue;
      }

      for (;;) {
        while (status & pts_event_pending) {
          struct pt_event ev;
          status = pt_insn_event(decoder.get(), &ev, sizeof(ev));
          if (status < 0) {
            break;
          }

          uint64_t pos = 0;
          pt_insn_get_offset(decoder.get(), &pos);
          PyObjPtr event(newEvent(ev, pos, tscConverter));

          if (!event) {
            return nullptr;
          }

          if (PyList_Append(events.get(), event.get()) < 0) {
            return nullptr;
          }
        }

        if (status < 0) {
          break;
        }

        if (status & pts_eos) {
          status = -pts_eos;
          break;
        }

        status = pt_insn_next(decoder.get(), &insn, sizeof(insn));

        if (insn.iclass != ptic_error) {
          auto instruction = newInstruction(insn.ip, insn.size, insn.iclass);
          if (!instruction) {
            return nullptr;
          }
          if (PyList_Append(events.get(), instruction.get()) < 0) {
            return nullptr;
          }
        }

        if (status < 0) {
          break;
        }
      }

      if (status == -pts_eos) {
        return events;
      }
    }
  }

private:
  PtImage image;
  PtInsnDecoder decoder;

  TscConverter tscConverter;
};

std::optional<Decoder> setupDecoder(Config &config) {
  int r = pt_cpu_errata(&config.config.errata, &config.config.cpu);
  if (r < 0) {
    PyErr_Format(PtError.get(), "cannot get cpu errata from cpu type: %s",
                 pt_errstr(pt_errcode(r)));
    return {};
  }

  PtInsnDecoder decoder(pt_insn_alloc_decoder(&config.config));
  if (!decoder) {
    PyErr_Format(PtError.get(), "cannot allocate instruction decoder");
    return {};
  }

  PtImage image(pt_image_alloc("hase"));
  if (!image) {
    PyErr_Format(PtError.get(), "cannot allocate memory image");
    return {};
  }

  r = pt_insn_set_image(decoder.get(), image.get());

  if (r < 0) {
    PyErr_Format(PtError.get(), "failed to set image: %s",
                 pt_errstr(pt_errcode(r)));
    return {};
  }

  return Decoder(std::move(image), std::move(decoder), config.tscConverter);
}

PyObject *decode(PyObject *self, PyObject *args, PyObject *kwdict) {
  auto config = getConfig(args, kwdict);
  if (!config) {
    return nullptr;
  }

  auto decoder = setupDecoder(*config);
  if (!decoder) {
    return nullptr;
  }

  for (auto obj : config->sharedObjects) {
    int r = decoder->addSharedObject(obj);
    if (r < 0) {
      return nullptr;
    }
  }

  auto events = decoder->run();
  if (!events) {
    return nullptr;
  }
  return events.release();
}
} // namespace hase::pt
