#include "tsc.h"
#include <assert.h>

namespace hase::pt {
TscConverter::TscConverter(uint64_t timeZero, uint16_t timeShift,
                           uint32_t timeMult)
    : timeZero(timeZero), timeShift(timeShift), timeMult(timeMult) {
  assert(timeMult != 0);
}

uint64_t TscConverter::tscToPerfTime(uint64_t tsc) {
  uint64_t quot = (tsc >> timeShift) * timeMult;
  uint64_t rem = ((tsc & ((1ull << timeShift) - 1)) * timeMult) >> timeShift;
  return timeZero + quot + rem;
}

uint64_t TscConverter::perfTimeToTsc(uint64_t time) {
  time -= timeZero;
  return ((time / timeMult) << timeShift) +
         (((time % timeMult) << timeShift) / timeMult);
}
} // namespace hase::pt
