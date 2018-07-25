#include <cstdint>

namespace hase::pt {
class TscConverter {
public:
  TscConverter(uint64_t timeZero, uint16_t timeShift, uint32_t timeMult);

  uint64_t tscToPerfTime(uint64_t tsc);
  uint64_t perfTimeToTsc(uint64_t time);

private:
  uint64_t timeZero;
  uint16_t timeShift;
  uint32_t timeMult;
};
} // namespace hase::pt
