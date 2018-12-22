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

enum pt_insn_class {
  /* The instruction could not be classified. */
  ptic_error,

  /* The instruction is something not listed below. */
  ptic_other,

  /* The instruction is a near (function) call. */
  ptic_call,

  /* The instruction is a near (function) return. */
  ptic_return,

  /* The instruction is a near unconditional jump. */
  ptic_jump,

  /* The instruction is a near conditional jump. */
  ptic_cond_jump,

  /* The instruction is a call-like far transfer.
   * E.g. SYSCALL, SYSENTER, or FAR CALL.
   */
  ptic_far_call,

  /* The instruction is a return-like far transfer.
   * E.g. SYSRET, SYSEXIT, IRET, or FAR RET.
   */
  ptic_far_return,

  /* The instruction is a jump-like far transfer.
   * E.g. FAR JMP.
   */
  ptic_far_jump,

  /* The instruction is a PTWRITE. */
  ptic_ptwrite
};

/** An execution mode. */
enum pt_exec_mode { ptem_unknown, ptem_16bit, ptem_32bit, ptem_64bit };

/** The maximal size of an instruction. */
enum { pt_max_insn_size = 15 };

struct pt_insn {
  /** The virtual address in its process. */
  uint64_t ip;

  /** The image section identifier for the section containing this
   * instruction.
   *
   * A value of zero means that the section did not have an identifier.
   * The section was not added via an image section cache or the memory
   * was read via the read memory callback.
   */
  int isid;

  /** The execution mode. */
  enum pt_exec_mode mode;

  /** A coarse classification. */
  enum pt_insn_class iclass;

  /** The raw bytes. */
  uint8_t raw[pt_max_insn_size];

  /** The size in bytes. */
  uint8_t size;

  /** A collection of flags giving additional information:
   *
   * - the instruction was executed speculatively.
   */
  uint32_t speculative : 1;

  /** - this instruction is truncated in its image section.
   *
   *    It starts in the image section identified by \@isid and continues
   *    in one or more other sections.
   */
  uint32_t truncated : 1;
};

/** Decoder status flags. */
enum pt_status_flag {
  /** There is an event pending. */
  pts_event_pending = 1,

  /** The address has been suppressed. */
  pts_ip_suppressed = 2,

  /** There is no more trace data available. */
  pts_eos = 4
};

/** Event types. */
enum pt_event_type {
  /* Tracing has been enabled/disabled. */
  ptev_enabled,
  ptev_disabled,

  /* Tracing has been disabled asynchronously. */
  ptev_async_disabled,

  /* An asynchronous branch, e.g. interrupt. */
  ptev_async_branch,

  /* A synchronous paging event. */
  ptev_paging,

  /* An asynchronous paging event. */
  ptev_async_paging,

  /* Trace overflow. */
  ptev_overflow,

  /* An execution mode change. */
  ptev_exec_mode,

  /* A transactional execution state change. */
  ptev_tsx,

  /* Trace Stop. */
  ptev_stop,

  /* A synchronous vmcs event. */
  ptev_vmcs,

  /* An asynchronous vmcs event. */
  ptev_async_vmcs,

  /* Execution has stopped. */
  ptev_exstop,

  /* An MWAIT operation completed. */
  ptev_mwait,

  /* A power state was entered. */
  ptev_pwre,

  /* A power state was exited. */
  ptev_pwrx,

  /* A PTWRITE event. */
  ptev_ptwrite,

  /* A timing event. */
  ptev_tick,

  /* A core:bus ratio event. */
  ptev_cbr,

  /* A maintenance event. */
  ptev_mnt
};

/** An event. */
struct pt_event {
  /** The type of the event. */
  enum pt_event_type type;

  /** A flag indicating that the event IP has been suppressed. */
  uint32_t ip_suppressed : 1;

  /** A flag indicating that the event is for status update. */
  uint32_t status_update : 1;

  /** A flag indicating that the event has timing information. */
  uint32_t has_tsc : 1;

  /** The time stamp count of the event.
   *
   * This field is only valid if \@has_tsc is set.
   */
  uint64_t tsc;

  /** The number of lost mtc and cyc packets.
   *
   * This gives an idea about the quality of the \@tsc.  The more packets
   * were dropped, the less precise timing is.
   */
  uint32_t lost_mtc;
  uint32_t lost_cyc;

  /* Reserved space for future extensions. */
  uint64_t reserved[2];

  /** Event specific data. */
  union {
    /** Event: enabled. */
    struct {
      /** The address at which tracing resumes. */
      uint64_t ip;

      /** A flag indicating that tracing resumes from the IP
       * at which tracing had been disabled before.
       */
      uint32_t resumed : 1;
    } enabled;

    /** Event: disabled. */
    struct {
      /** The destination of the first branch inside a
       * filtered area.
       *
       * This field is not valid if \@ip_suppressed is set.
       */
      uint64_t ip;

      /* The exact source ip needs to be determined using
       * disassembly and the filter configuration.
       */
    } disabled;

    /** Event: async disabled. */
    struct {
      /** The source address of the asynchronous branch that
       * disabled tracing.
       */
      uint64_t at;

      /** The destination of the first branch inside a
       * filtered area.
       *
       * This field is not valid if \@ip_suppressed is set.
       */
      uint64_t ip;
    } async_disabled;

    /** Event: async branch. */
    struct {
      /** The branch source address. */
      uint64_t from;

      /** The branch destination address.
       *
       * This field is not valid if \@ip_suppressed is set.
       */
      uint64_t to;
    } async_branch;

    /** Event: paging. */
    struct {
      /** The updated CR3 value.
       *
       * The lower 5 bit have been zeroed out.
       * The upper bits have been zeroed out depending on the
       * maximum possible address.
       */
      uint64_t cr3;

      /** A flag indicating whether the cpu is operating in
       * vmx non-root (guest) mode.
       */
      uint32_t non_root : 1;

      /* The address at which the event is effective is
       * obvious from the disassembly.
       */
    } paging;

    /** Event: async paging. */
    struct {
      /** The updated CR3 value.
       *
       * The lower 5 bit have been zeroed out.
       * The upper bits have been zeroed out depending on the
       * maximum possible address.
       */
      uint64_t cr3;

      /** A flag indicating whether the cpu is operating in
       * vmx non-root (guest) mode.
       */
      uint32_t non_root : 1;

      /** The address at which the event is effective. */
      uint64_t ip;
    } async_paging;

    /** Event: overflow. */
    struct {
      /** The address at which tracing resumes after overflow.
       *
       * This field is not valid, if ip_suppressed is set.
       * In this case, the overflow resolved while tracing
       * was disabled.
       */
      uint64_t ip;
    } overflow;

    /** Event: exec mode. */
    struct {
      /** The execution mode. */
      enum pt_exec_mode mode;

      /** The address at which the event is effective. */
      uint64_t ip;
    } exec_mode;

    /** Event: tsx. */
    struct {
      /** The address at which the event is effective.
       *
       * This field is not valid if \@ip_suppressed is set.
       */
      uint64_t ip;

      /** A flag indicating speculative execution mode. */
      uint32_t speculative : 1;

      /** A flag indicating speculative execution aborts. */
      uint32_t aborted : 1;
    } tsx;

    /** Event: vmcs. */
    struct {
      /** The VMCS base address.
       *
       * The address is zero-extended with the lower 12 bits
       * all zero.
       */
      uint64_t base;

      /* The new VMCS base address should be stored and
       * applied on subsequent VM entries.
       */
    } vmcs;

    /** Event: async vmcs. */
    struct {
      /** The VMCS base address.
       *
       * The address is zero-extended with the lower 12 bits
       * all zero.
       */
      uint64_t base;

      /** The address at which the event is effective. */
      uint64_t ip;

      /* An async paging event that binds to the same IP
       * will always succeed this async vmcs event.
       */
    } async_vmcs;

    /** Event: execution stopped. */
    struct {
      /** The address at which execution has stopped.  This is
       * the last instruction that did not complete.
       *
       * This field is not valid, if \@ip_suppressed is set.
       */
      uint64_t ip;
    } exstop;

    /** Event: mwait. */
    struct {
      /** The address of the instruction causing the mwait.
       *
       * This field is not valid, if \@ip_suppressed is set.
       */
      uint64_t ip;

      /** The mwait hints (eax).
       *
       * Reserved bits are undefined.
       */
      uint32_t hints;

      /** The mwait extensions (ecx).
       *
       * Reserved bits are undefined.
       */
      uint32_t ext;
    } mwait;

    /** Event: power state entry. */
    struct {
      /** The resolved thread C-state. */
      uint8_t state;

      /** The resolved thread sub C-state. */
      uint8_t sub_state;

      /** A flag indicating whether the C-state entry was
       * initiated by h/w.
       */
      uint32_t hw : 1;
    } pwre;

    /** Event: power state exit. */
    struct {
      /** The core C-state at the time of the wake. */
      uint8_t last;

      /** The deepest core C-state achieved during sleep. */
      uint8_t deepest;

      /** The wake reason:
       *
       * - due to external interrupt received.
       */
      uint32_t interrupt : 1;

      /** - due to store to monitored address. */
      uint32_t store : 1;

      /** - due to h/w autonomous condition such as HDC. */
      uint32_t autonomous : 1;
    } pwrx;

    /** Event: ptwrite. */
    struct {
      /** The address of the ptwrite instruction.
       *
       * This field is not valid, if \@ip_suppressed is set.
       *
       * In this case, the address is obvious from the
       * disassembly.
       */
      uint64_t ip;

      /** The size of the below \@payload in bytes. */
      uint8_t size;

      /** The ptwrite payload. */
      uint64_t payload;
    } ptwrite;

    /** Event: tick. */
    struct {
      /** The instruction address near which the tick occured.
       *
       * A timestamp can sometimes be attributed directly to
       * an instruction (e.g. to an indirect branch that
       * receives CYC + TIP) and sometimes not (e.g. MTC).
       *
       * This field is not valid, if \@ip_suppressed is set.
       */
      uint64_t ip;
    } tick;

    /** Event: cbr. */
    struct {
      /** The core:bus ratio. */
      uint16_t ratio;
    } cbr;

    /** Event: mnt. */
    struct {
      /** The raw payload. */
      uint64_t payload;
    } mnt;
  } variant;
};

struct decoder;

int decoder_new(struct decoder_config *c, struct decoder **d);
int decoder_sync_forward(struct decoder *d);
int decoder_next_event(struct decoder *d, struct pt_event *ev);
int decoder_next_instruction(struct decoder *d, struct pt_insn *insn);
const char *decoder_get_error(int code);
void decoder_free(struct decoder *d);
