#include "setup.h"

#include <fcntl.h>
#include <intel-pt.h>
#include <sys/stat.h>
#include <unistd.h>

namespace hase::pt {

std::tuple<int, std::optional<Setup>> getSetup(struct decoder_config &c) {
  struct pt_config config;
  std::vector<decoder_shared_object> sharedObjects;
  pt_config_init(&config);

  config.flags.variant.block.end_on_call = 1;
  config.flags.variant.block.end_on_jump = 1;

  config.cpu.vendor = pcv_intel;
  config.cpu.family = c.cpu_family;
  config.cpu.model = c.cpu_model;
  config.cpu.stepping = c.cpu_stepping;
  config.cpuid_0x15_eax = c.cpuid_0x15_eax;
  config.cpuid_0x15_ebx = c.cpuid_0x15_ebx;
  config.mtc_freq = 2;
  // trace buffer
  config.begin = nullptr;
  config.end = nullptr;

  config.cpuid_0x15_eax = (uint32_t)c.cpuid_0x15_eax;
  config.cpuid_0x15_ebx = (uint32_t)c.cpuid_0x15_ebx;

  sharedObjects.reserve(c.shared_object_count);
  for (size_t i = 0; i < c.shared_object_count; i++) {
    sharedObjects.push_back(c.shared_objects[i]);
  }

  int fd = open(c.trace_path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "failed to open '%s': %s\n", c.trace_path, strerror(-fd));
    return {-pte_invalid, std::nullopt};
  }

  struct stat sb;
  int r = fstat(fd, &sb);
  if (r < 0) {
    close(fd);
    fprintf(stderr, "failed to stat '%s': %s\n", c.trace_path, strerror(-fd));
    return {-pte_invalid, std::nullopt};
  }

  auto trace = Mmap::create(nullptr, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (!trace) {
    fprintf(stderr, "failed to mmap '%s': %s\n", c.trace_path, strerror(-fd));
    return {-pte_invalid, std::nullopt};
  }

  config.begin = trace->begin();
  config.end = trace->end();
  Setup setup{
      config,                   // config
      std::move(sharedObjects), // sharedObjects
      *std::move(trace),        // trace
  };

  return {0, std::move(setup)};
}
} // namespace hase::pt
