#pragma once

#include <intel-pt.h>
#include <libipt-sb.h>
#include <memory>

namespace hase::pt {

struct PtImageSectionCacheDeleter {
  void operator()(struct pt_image_section_cache *const iscache) {
    pt_iscache_free(iscache);
  }
};
typedef std::unique_ptr<struct pt_image_section_cache,
                        PtImageSectionCacheDeleter>
    PtImageSectionCache;

struct PtSbSessionDeleter {
  void operator()(struct pt_sb_session *const session) { pt_sb_free(session); }
};
typedef std::unique_ptr<struct pt_sb_session, PtSbSessionDeleter> PtSbSession;

struct PtInsnDecoderDeleter {
  void operator()(struct pt_insn_decoder *const decoder) {
    pt_insn_free_decoder(decoder);
  }
};
typedef std::unique_ptr<struct pt_insn_decoder, PtInsnDecoderDeleter>
    PtInsnDecoder;

struct PtImageAllocDeleter {
  void operator()(struct pt_image *const image) { pt_image_free(image); }
};
typedef std::unique_ptr<struct pt_image, PtImageAllocDeleter> PtImage;
} // namespace hase::pt
