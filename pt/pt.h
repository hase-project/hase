#pragma once
#include <intel-pt.h>
#include <stddef.h>
#include <stdint.h>

extern "C" {
struct decoder_shared_object {
  char *filename;
  uint64_t offset;
  uint64_t size;
  uint64_t vaddr;
};

struct decoder_config {
  char *trace_path;
  uint16_t cpu_family;
  uint8_t cpu_model;
  uint8_t cpu_stepping;
  uint32_t cpuid_0x15_eax, cpuid_0x15_ebx;
  size_t shared_object_count;
  struct decoder_shared_object *shared_objects;
};

struct decoder;

int decoder_new(struct decoder_config *c, struct decoder **d);
int decoder_sync_forward(struct decoder *d);
int decoder_next_event(struct decoder *d, struct pt_event *ev);
int decoder_next_instruction(struct decoder *d, struct pt_insn *insn);
const char *decoder_get_error(int code);
void decoder_free(struct decoder *d);
}
