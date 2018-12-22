#include "pt.h"

#include "decoder.h"
#include "setup.h"

#include <cassert>
#include <optional>
#include <tuple>

using namespace hase::pt;

extern "C" {
int decoder_new(struct decoder_config *c, struct decoder **d) {
  assert(c != nullptr);
  *d = nullptr;

  auto [result, setup] = getSetup(*c);
  if (result < 0) {
    return result;
  }

  auto [result2, internal_decoder] = createDecoder(*std::move(setup));
  if (result2 < 0) {
    return result2;
  }

  *d = reinterpret_cast<struct decoder *>(internal_decoder->release());

  return 0;
}

int decoder_sync_forward(struct decoder *d) {
  assert(d != nullptr);
  auto decoder = reinterpret_cast<Decoder *>(d);
  return decoder->syncForward();
}

int decoder_next_event(struct decoder *d, struct pt_event *ev) {
  assert(d != nullptr && ev != nullptr);
  auto decoder = reinterpret_cast<Decoder *>(d);
  return decoder->nextEvent(*ev);
}

int decoder_next_instruction(struct decoder *d, struct pt_insn *insn) {
  assert(d != nullptr && insn != nullptr);
  auto decoder = reinterpret_cast<Decoder *>(d);
  return decoder->nextInstruction(*insn);
}

const char *decoder_get_error(int code) { return pt_errstr(pt_errcode(code)); }

void decoder_free(struct decoder *d) {
  if (d == nullptr) {
    return;
  }
  delete reinterpret_cast<Decoder *>(d);
}
}
