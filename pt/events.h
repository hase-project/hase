#pragma once

#include "ptr.h"

namespace hase::pt {
extern PyObjPtr Instruction;
extern PyObjPtr InstructionClass;
extern PyObjPtr EnableEvent;
extern PyObjPtr DisableEvent;
extern PyObjPtr AsyncDisableEvent;
extern PyObjPtr AsyncBranchEvent;
extern PyObjPtr PagingEvent;
extern PyObjPtr AsyncPagingEvent;
extern PyObjPtr OverflowEvent;
extern PyObjPtr ExecModeEvent;
extern PyObjPtr TsxEvent;
extern PyObjPtr StopEvent;
extern PyObjPtr VmcsEvent;
extern PyObjPtr AsyncVmcsEvent;
extern PyObjPtr ExstopEvent;
extern PyObjPtr MwaitEvent;
extern PyObjPtr PwreEvent;
extern PyObjPtr PwrxEvent;
extern PyObjPtr PtWriteEvent;
extern PyObjPtr TickEvent;
extern PyObjPtr CbrEvent;
extern PyObjPtr MntEvent;
} // namespace hase::pt
