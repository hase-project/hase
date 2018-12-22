#include "decoder.h"
#include "iostream"

namespace hase::pt {

Decoder::Decoder(PtImage image, PtInsnDecoder decoder, Setup setup)
    : image(std::move(image)), decoder(std::move(decoder)),
      setup(std::move(setup)){};

// add back later
// void diagnoseError(int errcode, struct pt_insn &insn) {
//  std::string ip;
//  uint64_t pos;
//  ip = intToHex(insn.ip);
//  int r = pt_insn_get_offset(decoder.get(), &pos);
//
//  if (r < 0) {
//    return PyObjPtr(PyErr_Format(
//        PtError.get(), "synchronisation failed at offset ? and ip %s: %s",
//        ip.c_str(), pt_errstr(pt_errcode(errcode))));
//  }
//  auto posStr = intToHex(pos);
//  return PyObjPtr(PyErr_Format(
//      PtError.get(), "synchronisation failed at offset %s and ip %s: %s",
//      posStr.c_str(), ip.c_str(), pt_errstr(pt_errcode(errcode))));
//}

int Decoder::syncForward() {
  uint64_t sync = 0;
  for (;;) {
    status = pt_insn_sync_forward(decoder.get());
    if (status < 0) {
      if (status == -pte_eos) {
        return status;
      }

      uint64_t newSync = 0;
      int r = pt_insn_get_offset(decoder.get(), &newSync);
      if (r < 0 || (newSync <= sync)) {
        return status;
      }

      sync = newSync;
      continue;
    } else {
      return status;
    }
  }
}

int Decoder::nextEvent(struct pt_event &ev) {
  return pt_insn_event(decoder.get(), &ev, sizeof(ev));
}

int Decoder::nextInstruction(struct pt_insn &insn) {
  return pt_insn_next(decoder.get(), &insn, sizeof(insn));
}

std::tuple<int, std::optional<std::unique_ptr<Decoder>>>
createDecoder(Setup setup) {
  int r = pt_cpu_errata(&setup.config.errata, &setup.config.cpu);
  if (r < 0) {
    return {r, std::nullopt};
  }

  PtInsnDecoder instDecoder(pt_insn_alloc_decoder(&setup.config));
  if (!instDecoder) {
    return {-ENOMEM, std::nullopt};
  }

  PtImage image(pt_image_alloc("hase"));
  if (!image) {
    return {-ENOMEM, std::nullopt};
  }

  r = pt_insn_set_image(instDecoder.get(), image.get());

  if (r < 0) {
    return {r, std::nullopt};
  }

  for (auto obj : setup.sharedObjects) {
    int r = pt_image_add_file(image.get(), obj.filename, obj.offset, obj.size,
                              nullptr, obj.vaddr);
    if (r < 0) {
      return {r, std::nullopt};
    }
  }

  auto decoder = std::make_unique<Decoder>(
      std::move(image), std::move(instDecoder), std::move(setup));
  return {0, std::move(decoder)};
}

} // namespace hase::pt
