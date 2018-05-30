#include <Python.h>

#include "decode.h"

#include <csignal>
#include <functional>
#include <iomanip>
#include <memory>
#include <sstream>
#include <iostream>

#include "config.h"
#include "instruction.h"
#include "pt.h"
#include "pt_error.h"
#include "ptr.h"

namespace hase::pt {

static int printError(int errcode, const char *filename, uint64_t offset,
                      void *priv) {
  const char *errstr, *severity;
  if (!filename)
    filename = "<unknown>";
  severity = errcode < 0 ? "error" : "warning";
  errstr = errcode < 0 ? pt_errstr(pt_errcode(errcode))
                       : pt_sb_errstr((enum pt_sb_error_code)errcode);
  if (!errstr)
    errstr = "<unknown error>";
  printf("[%s:%016" PRIx64 " sideband %s: %s]\n", filename, offset, severity,
         errstr);
  return 0;
}

static uint64_t pid = 0;
static uint64_t time = 0;

static int printSwitch(const struct pt_sb_context *context, void *callbackPtr) {
  struct pt_image *image;
  const char *name;

  auto callback = static_cast<PyObject *>(callbackPtr);
  PyObjPtr arglist(Py_BuildValue("(i)", pt_sb_ctx_pid(context)));
  pid = pt_sb_ctx_pid(context);
  time = pt_sb_ctx_tsc(context);
  PyObjPtr result(PyObject_CallObject(callback, arglist.get()));
  if (!result) {
    return -pte_internal;
  }

  image = pt_sb_ctx_image(context);
  if (!image)
    return -pte_internal;

  name = pt_image_name(image);
  if (!name)
    name = "<unknown>";

  printf("[context: %s]\n", name);

  return 0;
}

static std::string intToHex(uint64_t i) {
  std::stringstream stream;
  stream << "0x" << std::setfill('0') << std::setw(sizeof(uint64_t) * 2)
         << std::hex << i;
  return stream.str();
}

PyObjPtr newInstruction(uint64_t ip, uint8_t size) {
  PyObjPtr argList(Py_BuildValue("kB", ip, size));
  if (!argList) {
    return nullptr;
  }

  return PyObjPtr(PyObject_CallObject(Instruction.get(), argList.get()));
}

class Decoder {
public:
  Decoder(PtImageSectionCache iscache, PtSbSession session, PtImage image,
          PtInsnDecoder decoder)
      : iscache(std::move(iscache)), session(std::move(session)),
        image(std::move(image)), decoder(std::move(decoder)) {}

  int addSidebandDecoder(const struct pt_sb_pevent_config &pevent) {
    int r = pt_sb_alloc_pevent_decoder(session.get(), &pevent);
    if (r < 0) {
      PyErr_Format(PtError.get(), "error loading %s: %s", pevent.filename,
                   pt_errstr(pt_errcode(r)));
      return r;
    }
    return r;
  }

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
    int isid = pt_iscache_add_file(iscache.get(), obj.filename, obj.offset,
                                   obj.size, obj.vaddr);
    if (isid < 0) {
      PyErr_Format(PtError.get(),
                   "cannot add shared object %s to instruction cache: %s",
                   obj.filename, pt_errstr(pt_errcode(isid)));
      return isid;
    }

    int r = pt_image_add_cached(image.get(), iscache.get(), isid, nullptr);
    if (r < 0) {
      PyErr_Format(PtError.get(),
                   "cannot add shared object %s to instruction image: %s",
                   obj.filename, pt_errstr(pt_errcode(r)));
      return r;
    }

    return 0;
  }

  static void print_event(const struct pt_event *event, uint64_t offset) {
      printf("[");
   
      printf("%016" PRIx64 "  ", offset);

      if (event->has_tsc)
        printf("%016" PRIx64 "  ", event->tsc);
   
      switch (event->type) {
      case ptev_enabled:
        printf("%s", event->variant.enabled.resumed ? "resumed" :
               "enabled");
   
        printf(", ip: %016" PRIx64, event->variant.enabled.ip);
        break;
   
      case ptev_disabled:
        printf("disabled");
   
        if (!event->ip_suppressed)
          printf(", ip: %016" PRIx64, event->variant.disabled.ip);
        break;
   
      case ptev_async_disabled:
        printf("disabled");
   
        printf(", at: %016" PRIx64,
                event->variant.async_disabled.at);

        if (!event->ip_suppressed)
            printf(", ip: %016" PRIx64,
                    event->variant.async_disabled.ip);
        break;
   
      case ptev_async_branch:
        printf("interrupt");
   
          printf(", from: %016" PRIx64,
                 event->variant.async_branch.from);
        break;

     case ptev_paging:
        printf("paging, cr3: %016" PRIx64 "%s",
                event->variant.paging.cr3,
                event->variant.paging.non_root ? ", nr" : "");
        break;
     case ptev_async_paging:
        printf("paging, cr3: %016" PRIx64 "%s",
                event->variant.async_paging.cr3,
                event->variant.async_paging.non_root ? ", nr" : "");
        printf(", ip: %016" PRIx64,
                event->variant.async_paging.ip);
        break;
     case ptev_overflow:
        printf("overflow");
        if (!event->ip_suppressed)
            printf(", ip: %016" PRIx64, event->variant.overflow.ip);
        break;
     case ptev_exec_mode:
        printf("exec mode: %d", event->variant.exec_mode.mode);
        if (!event->ip_suppressed)
            printf(", ip: %016" PRIx64,
                    event->variant.exec_mode.ip);
        break;

     case ptev_tsx:
        if (event->variant.tsx.aborted)
            printf("aborted");
        else if (event->variant.tsx.speculative)
            printf("begin transaction");
        else
            printf("committed");
        if (!event->ip_suppressed)
            printf(", ip: %016" PRIx64, event->variant.tsx.ip);
        break;
     case ptev_stop:
        printf("stopped");
        break;
     case ptev_vmcs:
        printf("vmcs, base: %016" PRIx64, event->variant.vmcs.base);
        break;
     case ptev_async_vmcs:
        printf("vmcs, base: %016" PRIx64,
                event->variant.async_vmcs.base);
        printf(", ip: %016" PRIx64,
                event->variant.async_vmcs.ip);
        break;
     case ptev_exstop:
        printf("exstop");
        if (!event->ip_suppressed)
            printf(", ip: %016" PRIx64, event->variant.exstop.ip);
        break;
        case ptev_mwait:
      printf("mwait %" PRIx32 " %" PRIx32,
             event->variant.mwait.hints, event->variant.mwait.ext);
      if (!event->ip_suppressed)
        printf(", ip: %016" PRIx64, event->variant.mwait.ip);
      break;
    case ptev_pwre:
      printf("pwre c%u.%u", (event->variant.pwre.state + 1) & 0xf,
             (event->variant.pwre.sub_state + 1) & 0xf);
      if (event->variant.pwre.hw)
        printf(" hw");
      break;
    case ptev_pwrx:
      printf("pwrx ");
      if (event->variant.pwrx.interrupt)
        printf("int: ");
      if (event->variant.pwrx.store)
        printf("st: ");
      if (event->variant.pwrx.autonomous)
        printf("hw: ");
      printf("c%u (c%u)", (event->variant.pwrx.last + 1) & 0xf,
             (event->variant.pwrx.deepest + 1) & 0xf);
      break;
    case ptev_ptwrite:
      printf("ptwrite: %" PRIx64, event->variant.ptwrite.payload);
      if (!event->ip_suppressed)
        printf(", ip: %016" PRIx64, event->variant.ptwrite.ip);
      break;
    case ptev_tick:
      printf("tick");
      if (!event->ip_suppressed)
        printf(", ip: %016" PRIx64, event->variant.tick.ip);
      break;
    case ptev_cbr:
      printf("cbr: %x", event->variant.cbr.ratio);
      break;
    case ptev_mnt:
      printf("mnt: %" PRIx64, event->variant.mnt.payload);
      break;
    }
    printf("]\n");
  }

  PyObjPtr run() {
    PyObjPtr instructions(PyList_New(0));

    uint64_t sync = 0;

    int r = pt_sb_init_decoders(session.get());
    if (r < 0) {
      return PyObjPtr(PyErr_Format(PtError.get(),
                                   "failed to init sideband decoder: %s",
                                   pt_errstr(pt_errcode(r))));
    }

    struct pt_insn insn = {};

    for (;;) {
      int status = pt_insn_sync_forward(decoder.get());
      if (status < 0) {
        if (status == -pte_eos) {
          return instructions;
        }

        // Let's see if we made any progress.  If we haven't,
        // we likely never will.  Bail out.
        //
        // We intentionally report the error twice to indicate
        // that we tried to re-sync.  Maybe it even changed.
        //
        uint64_t newSync = 0;
        r = pt_insn_get_offset(decoder.get(), &newSync);
        if (r < 0 || (newSync <= sync)) {
          return diagnoseError(status, insn);
        }

        sync = newSync;
        continue;
      }

      for (;;) {
        while (status & pts_event_pending) {
          struct pt_event event;
          status = pt_insn_event(decoder.get(), &event, sizeof(event));
          if (status < 0) {
            break;
          }
          uint64_t pos = 0;
          pt_insn_get_offset(decoder.get(), &pos);
          print_event(&event, pos);

          struct pt_image *image = nullptr;
          status =
              pt_sb_event(session.get(), &image, &event, sizeof(event), stdout, ptsbp_verbose|ptsbp_tsc);
          if (status < 0) {
            break;
          }

          if (image) {
              status = pt_insn_set_image(decoder.get(), image);
              if (status < 0) {
                  break;
              }
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
        if (pid == 0x6473 && insn.ip == 0x00007f1a3d02b993) {
            if (status < 0) {
                std::cout << "should not error, got at ip " << intToHex(insn.ip) << " and time " << time << ": " << pt_errstr(pt_errcode(status)) << std::endl;
                if (status == -pte_bad_insn) {
                    std::cout << "got bad instructions" << std::endl;
                }
            } else {
                std::cout << "successfully decode " << intToHex(insn.ip) << std::endl;
            }
        }

        if (insn.iclass != ptic_error) {
          auto instruction = newInstruction(insn.ip, insn.size);
          if (!instruction) {
            return nullptr;
          }
          if (PyList_Append(instructions.get(), instruction.get()) < 0) {
            return nullptr;
          }
        }

        if (status < 0) {
          break;
        }

      }

      if (status == -pts_eos) {
        return instructions;
      }
    }
  }

private:
  PtImageSectionCache iscache;
  PtSbSession session;
  PtImage image;
  PtInsnDecoder decoder;
};

std::optional<Decoder> setupDecoder(Config &config) {
  PtImageSectionCache iscache(pt_iscache_alloc(NULL));
  if (!iscache) {
    PyErr_Format(PtError.get(), "cannot allocate image section cache");
    return {};
  }

  PtSbSession session(pt_sb_alloc(iscache.get()));
  if (!session) {
    PyErr_Format(PtError.get(), "cannot allocate sideband session");
    return {};
  }

  pt_sb_notify_error(session.get(), printError, nullptr);

  PtImage image(pt_image_alloc(nullptr));
  if (!image) {
    PyErr_Format(PtError.get(), "cannot allocate memory image");
    return {};
  }

  int r = pt_cpu_errata(&config.config.errata, &config.config.cpu);
  if (r < 0) {
    PyErr_Format(PtError.get(), "cannot get cpu errata from cpu type: %s",
                 pt_errstr(pt_errcode(r)));
    return {};
  }

  pt_sb_notify_switch(session.get(), printSwitch, config.switchCallback);

  PtInsnDecoder decoder(pt_insn_alloc_decoder(&config.config));
  if (!decoder) {
    PyErr_Format(PtError.get(), "cannot allocate instruction decoder");
    return {};
  }

  r = pt_insn_set_image(decoder.get(), image.get());

  if (r < 0) {
    PyErr_Format(PtError.get(), "failed to set image: %s",
                 pt_errstr(pt_errcode(r)));
    return {};
  }

  return Decoder(std::move(iscache), std::move(session), std::move(image),
                 std::move(decoder));
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

  auto primary = true;

  for (auto filename : config->perfEventFilenames) {
    auto pevent = config->peventConfig;
    if (primary) {
      pevent.primary = 1;
      primary = false;
    } else {
      pevent.primary = 0;
    }
    pevent.filename = filename;
    int r = decoder->addSidebandDecoder(pevent);
    if (r < 0) {
      return nullptr;
    }
  }

  for (auto obj : config->sharedObjects) {
    int r = decoder->addSharedObject(obj);
    if (r < 0) {
      return nullptr;
    }
  }

  auto branches = decoder->run();
  if (!branches) {
    return nullptr;
  }
  return branches.release();
}
} // namespace hase::pt
