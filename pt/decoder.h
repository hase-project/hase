#pragma once

#include "pt_utils.h"
#include "setup.h"

#include <memory>
#include <optional>
#include <tuple>

namespace hase::pt {
class Decoder {
public:
  Decoder(PtImage image, PtInsnDecoder decoder, Setup setup);
  int syncForward();
  int nextEvent(struct pt_event &ev);
  int nextInstruction(struct pt_insn &insn);

private:
  int status = 0;
  PtImage image;
  PtInsnDecoder decoder;
  Setup setup;
};
std::tuple<int, std::optional<std::unique_ptr<Decoder>>>
createDecoder(Setup setup);
} // namespace hase::pt

// PyObjPtr Decoder::run() {
//    PyObjPtr events(PyList_New(0));
//
//    uint64_t sync = 0;
//
//    struct pt_insn insn = {};
//
//    for (;;) {
//      int status = pt_insn_sync_forward(decoder.get());
//      if (status < 0) {
//        if (status == -pte_eos) {
//          return events;
//        }
//
//        // Let's see if we made any progress.  If we haven't,
//        // we likely never will.  Bail out.
//        //
//        // We intentionally report the error twice to indicate
//        // that we tried to re-sync.  Maybe it even changed.
//        //
//        uint64_t newSync = 0;
//        int r = pt_insn_get_offset(decoder.get(), &newSync);
//        if (r < 0 || (newSync <= sync)) {
//          return status;
//        }
//
//        sync = newSync;
//        continue;
//      }
//
//      for (;;) {
//        while (status & pts_event_pending) {
//          struct pt_event ev;
//          status = pt_insn_event(decoder.get(), &ev, sizeof(ev));
//          if (status < 0) {
//            break;
//          }
//
//          uint64_t pos = 0;
//          pt_insn_get_offset(decoder.get(), &pos);
//          PyObjPtr event(newEvent(ev, pos, tscConverter));
//
//          if (!event) {
//            return nullptr;
//          }
//
//          if (PyList_Append(events.get(), event.get()) < 0) {
//            return nullptr;
//          }
//        }
//
//        if (status < 0) {
//          break;
//        }
//
//        if (status & pts_eos) {
//          status = -pts_eos;
//          break;
//        }
//
//        status = pt_insn_next(decoder.get(), &insn, sizeof(insn));
//
//        if (insn.iclass != ptic_error) {
//          auto instruction = newInstruction(insn.ip, insn.size, insn.iclass);
//          if (!instruction) {
//            return nullptr;
//          }
//          if (PyList_Append(events.get(), instruction.get()) < 0) {
//            return nullptr;
//          }
//        }
//
//        if (status < 0) {
//          break;
//        }
//      }
//
//      if (status == -pts_eos) {
//        return events;
//      }
//    }
//  }
