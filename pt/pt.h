#pragma once

#include <intel-pt.h>
#include <memory>

namespace hase::pt {
struct PtInsnDecoderDeleter {
  void operator()(struct pt_insn_decoder *const decoder) {
    pt_insn_free_decoder(decoder);
  }
};
typedef std::unique_ptr<struct pt_insn_decoder, PtInsnDecoderDeleter>
    PtInsnDecoder;

struct PtImageDeleter {
  void operator()(struct pt_image *const image) { pt_image_free(image); }
};
typedef std::unique_ptr<struct pt_image, PtImageDeleter> PtImage;
} // namespace hase::pt
