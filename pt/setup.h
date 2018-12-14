#pragma once

#include "mmap.h"
extern "C" {
#include "pt.h"
}

#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <intel-pt.h>

namespace hase::pt {
typedef struct {
  struct pt_config config;
  std::vector<decoder_shared_object> sharedObjects;
  Mmap trace;
} Setup;

std::tuple<int, std::optional<Setup>> getSetup(struct decoder_config &c);
} // namespace hase::pt
