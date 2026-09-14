// SPDX-License-Identifier: MIT

#include <atomic>
#include <iterator> // ml760: std::size for the HandleImageMap stack batch
#include <cstdlib>  // ml623: getenv/strtoull for the IR-capture target
#include <cstring>  // ml623: strlen
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include "InvalidationTracker.h"
#include <windef.h>
#include <winternl.h>

/* ml623: targeted IR capture target (defined in FEXCore PassManager.cpp). File scope on
 * purpose -- an extern "C" at block scope is a compile error and cost a build earlier. */
extern "C" uint64_t FEX_MadeiraIRCapTarget;

/* ml648: defined in the ARM64EC alias TU. Declared at FILE scope — an
 * extern "C" declaration is illegal at block scope, and declaring it inside
 * namespace FEX::Windows would mangle it as FEX::Windows::ios_fex_mono_arm. */
#ifdef FEX_IOS_HOST
extern "C" void ios_fex_mono_arm(uint64_t Base, uint64_t End);
#endif

namespace FEX::Windows {

/* iOS-Madeira ml760: RE-ENTRANCY GUARD FOR IntervalsLock / CodeInvalidationMutex.
 *
 * THE DEADLOCK. IntervalsLock is a plain std::shared_mutex (InvalidationTracker.h) and is
 * therefore NOT recursive. Every write path in this file allocates while holding it:
 * IntervalList::Insert/Remove call fextl::vector::insert/erase, and LogMan::Msg::EFmt formats
 * into fextl storage. When FEX's allocator has to grow it issues NtAllocateVirtualMemory, wine
 * calls back into NotifyMemoryAlloc, and that lands in HandleMemoryProtectionNotification ->
 * std::unique_lock(IntervalsLock) ON THE SAME THREAD. A non-recursive mutex parks forever.
 *
 * Observed (main-process launch, module #29 of the ml710 NotifyImageMap path): the FIRST
 * [iOS-xins] line of a two-executable-section module printed, the second never did, and the
 * initial thread sat in __ulock_wait2 (x16=0x220, x0=0x1000001 = UL_COMPARE_AND_WAIT) with
 * [alert-ring] pinned at zero for the rest of the run. FEX's own tree already documents the
 * identical signature for the ImageTracker/CodeInvalidationMutex variant of this bug
 * (ARM64EC/Module.cpp:1326-1330) -- same shape, different lock.
 *
 * THE GUARD. A PER-THREAD depth counter is raised for exactly as long as this object holds one
 * of its locks. Every notification entry point tests it first and, when it is non-zero, logs
 * and RETURNS WITHOUT TOUCHING A LOCK.
 *
 * ⛔ IT IS DELIBERATELY NOT A `thread_local`. ml412 (ARM64EC/Module.cpp:1452) records that
 * mingw TLS access loads TEB->ThreadLocalStoragePointer ([x18+0x58]), which is still NULL when
 * the loader issues its first callbacks -- it crashed BTCpu64NotifyReadFile at addr=0. This
 * guard runs on exactly those early loader paths (NotifyImageMap, the constructor's
 * VirtualQuery sweep), so a thread_local here would be a launch crash rather than a fix.
 * Instead the thread is keyed by its TEB POINTER (x18, no TLS indirection) into a small
 * lock-free slot table. Nothing is written into the TEB itself: Instrumentation[9] is already
 * claimed by ml412 and [10] by wine's EC ntdll pump beacon, and guessing a free slot across
 * three components is how those collisions happen in the first place.
 *
 * WHY THIS CANNOT DEADLOCK: the re-entrant call performs no lock acquisition at all, so there
 * is no wait to be blocked on; and the counter is per-thread, so a genuinely concurrent
 * thread's notification is unaffected and still blocks normally on the mutex.
 *
 * FAIL-OPEN, NOT FAIL-SILENT: if the slot table is exhausted the thread is simply untracked,
 * the check returns false and behaviour is exactly what it was before this change (including
 * the deadlock risk). That is reported once rather than pretended away.
 *
 * WHAT IS SKIPPED, precisely. A re-entrant notification can only describe memory that some
 * call already inside this tracker caused the OS to change:
 *   - allocator growth for our own interval vectors / log buffers (FEX host heap -- never
 *     guest code, and the guest never has a mapping for it);
 *   - the NtProtectVirtualMemory calls this class itself issues to trap/untrap RWX intervals
 *     (ProtectRWXIntervalsInternal, DisableSMCDetection, HandleRWXAccessViolation), whose
 *     effect is already recorded in the interval lists by the very code making the call.
 * In both cases re-applying it would be a no-op at best. It is NOT free of risk in principle
 * -- if some future caller ever allocates guest-visible executable memory from inside a
 * tracker lock, that range would go unregistered -- so every skip is counted and logged
 * rather than silently dropped.
 *
 * The log itself allocates, so re-entry from inside the re-entry report is suppressed by a
 * per-slot flag; without it the report could recurse until the stack is gone. */
namespace {
constexpr unsigned TrackerSlotCount = 64;

// Key: the thread's TEB pointer (x18). nullptr = free slot.
std::atomic<void*> TrackerSlotTeb[TrackerSlotCount] {};
// Depth and report flag are only ever touched by the thread that owns the slot, so they need
// no atomicity of their own -- publication is handled by the TEB pointer's release store.
uint32_t TrackerSlotDepth[TrackerSlotCount] {};
uint8_t TrackerSlotReporting[TrackerSlotCount] {};
std::atomic<uint32_t> TrackerSlotOverflow {0};

int TrackerFindSlot(void* Teb) {
  if (!Teb) {
    return -1;
  }
  for (unsigned i = 0; i < TrackerSlotCount; i++) {
    if (TrackerSlotTeb[i].load(std::memory_order_acquire) == Teb) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

int TrackerClaimSlot(void* Teb) {
  const int Existing = TrackerFindSlot(Teb);
  if (Existing >= 0 || !Teb) {
    return Existing;
  }
  for (unsigned i = 0; i < TrackerSlotCount; i++) {
    void* Expected = nullptr;
    if (TrackerSlotTeb[i].compare_exchange_strong(Expected, Teb, std::memory_order_acq_rel, std::memory_order_relaxed)) {
      TrackerSlotDepth[i] = 0;
      TrackerSlotReporting[i] = 0;
      return static_cast<int>(i);
    }
  }
  return -1;
}

/// Raised for exactly the scope in which an InvalidationTracker lock is held.
struct TrackerLockScope {
  int Slot;
  TrackerLockScope()
    : Slot {TrackerClaimSlot(NtCurrentTeb())} {
    if (Slot >= 0) {
      ++TrackerSlotDepth[Slot];
    } else {
      const auto N = TrackerSlotOverflow.fetch_add(1) + 1;
      if (N == 1) {
        LogMan::Msg::EFmt("[xins] ml760 re-entrancy slot table EXHAUSTED ({} threads) — this thread is "
                          "UNTRACKED and reverts to the pre-ml760 (deadlock-capable) behaviour",
                          TrackerSlotCount);
      }
    }
  }
  ~TrackerLockScope() {
    if (Slot < 0) {
      return;
    }
    if (--TrackerSlotDepth[Slot] == 0) {
      TrackerSlotTeb[Slot].store(nullptr, std::memory_order_release);
    }
  }
  TrackerLockScope(const TrackerLockScope&) = delete;
  TrackerLockScope& operator=(const TrackerLockScope&) = delete;
};

/// Returns true when this thread is already inside a tracker lock, i.e. the caller must bail
/// out instead of locking. Rate-capped so a storm cannot drown the log.
bool TrackerReentered(const char* Site, uint64_t Address, uint64_t Size) {
  const int Slot = TrackerFindSlot(NtCurrentTeb());
  if (Slot < 0 || TrackerSlotDepth[Slot] == 0) {
    return false;
  }
  if (TrackerSlotReporting[Slot]) {
    return true;
  }
  static std::atomic<uint32_t> ReentryCount;
  const auto N = ReentryCount.fetch_add(1) + 1;
  if (N <= 32 || !(N & 0xFF)) {
    TrackerSlotReporting[Slot] = 1;
    LogMan::Msg::EFmt("[xins] RE-ENTRY #{} depth={} from {} addr={:#x} size={:#x} — SKIPPED, no lock taken "
                      "(a nested notification raised while this thread holds IntervalsLock would self-deadlock; "
                      "the range is allocator/tracker-owned, not guest code)",
                      N, TrackerSlotDepth[Slot], Site, Address, Size);
    TrackerSlotReporting[Slot] = 0;
  }
  return true;
}
} // namespace

InvalidationTracker::InvalidationTracker(FEXCore::Context::Context& CTX,
                                         const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads, uint64_t GuestBase)
  : CTX {CTX}
  , Threads {Threads}
  , GuestBase {GuestBase} {
  FEX_CONFIG_OPT(SMCChecks, SMCCHECKS);
  SMCDetectionDisabled = (SMCChecks == FEXCore::Config::CONFIG_SMC_NONE);

  MEMORY_BASIC_INFORMATION Info;
  uint64_t Address = 0;

  while (VirtualQuery(reinterpret_cast<LPCVOID>(Address), &Info, sizeof(Info))) {
    uint64_t BaseAddress = reinterpret_cast<uint64_t>(Info.BaseAddress);
    if (Info.State == MEM_COMMIT) {
      HandleMemoryProtectionNotification(BaseAddress, Info.RegionSize, Info.Protect);
    }

    Address = BaseAddress + Info.RegionSize;
  }
}

static bool ProtHasExec(ULONG Prot) {
  return (Prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool ProtIsReadable(ULONG Prot) {
  return (Prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                  PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool ProtIsWritable(ULONG Prot) {
  return (Prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

void InvalidationTracker::HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot) {
  // ml760: this is the re-entry point the allocator reaches via NotifyMemoryAlloc. See the
  // guard's comment at the top of this file.
  if (TrackerReentered("HandleMemoryProtectionNotification", Address, Size)) {
    return;
  }

  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;

  const bool NeedsInvalidate = [&]() {
    TrackerLockScope Reentry;
    std::unique_lock Lock(IntervalsLock);

    FEXCore::IntervalList<uint64_t>::Interval ProtInterval {AlignedBase, AlignedBase + AlignedSize};

    const bool HasExec = ProtHasExec(Prot);
    const bool EffectiveExec = HasExec || (DEPDisabled && ProtIsReadable(Prot));
    const bool EffectiveRWX = EffectiveExec && ProtIsWritable(Prot);

    if (EffectiveExec) {
      XIntervals.Insert(ProtInterval);
      if (EffectiveRWX) {
        LogMan::Msg::DFmt("Add SMC interval: {:X} - {:X}", AlignedBase, AlignedBase + AlignedSize);
        RWXIntervals.Insert(ProtInterval);
      }
      if (DEPDisabled && !HasExec) {
        DEPPromotedIntervals.Insert(ProtInterval);
      }
      return true;
    } else if (XIntervals.Intersect(ProtInterval)) {
      /* iOS-Madeira ml208 ROOT-CAUSE FIX.
       *
       * A >=1GB non-executable range is an allocator reserving or managing a pool, never a
       * code-permission change. Removing exec intervals for it wipes the executable range
       * of EVERY module inside at once. Observed: PartitionAlloc reserving its 16GB soft
       * pool 0x7000000000-0x7400000000 erased libcef's .text (0x7388f41000-0x7393f7cd23),
       * after which the decoder reported NOEXEC at libcef code addresses, raised
       * FAULT_SIGSEGV and killed 42 webhelper threads.
       *
       * Note this arrives via NotifyMemoryAlloc (ARM64EC/Module.cpp), NOT NotifyMemoryProtect
       * — an earlier fix guarding Wine's NtProtectVirtualMemory therefore never fired. The
       * guard belongs here, at the single choke point all three callers share.
       *
       * Only the REMOVAL branch is guarded: modules keep their own mappings and issue their
       * own notifications, so ignoring a bulk range cannot lose a genuine executability
       * transition, while the insert path above is left untouched so DEP promotion behaves
       * exactly as before. */
      if (AlignedSize >= (1ull << 30)) {
        LogMan::Msg::EFmt("[iOS-xrem] SUPPRESSED bulk non-exec {:#x}-{:#x} ({} MB) prot={:#x}", ProtInterval.Offset,
                          ProtInterval.End, AlignedSize >> 20, Prot);
        return false;
      }
      LogMan::Msg::EFmt("[iOS-xrem] via=protect tracker={} {:#x}-{:#x}", static_cast<void*>(this),
                        ProtInterval.Offset, ProtInterval.End);
      XIntervals.Remove(ProtInterval);
      RWXIntervals.Remove(ProtInterval);
      if (DEPDisabled) {
        DEPPromotedIntervals.Remove(ProtInterval);
      }
      return true;
    }

    return false;
  }();

  if (NeedsInvalidate) {
    // IntervalsLock cannot be held during invalidation
    InvalidateIntervalInternal(AlignedBase, AlignedSize);
  }
}

void InvalidationTracker::HandleProcessExecuteFlagsChange(ULONG Flags) {
  const bool DisableDEP = (Flags & MEM_EXECUTE_OPTION_ENABLE) != 0;

  // ml760: this whole body runs under BOTH locks and inserts/removes intervals (allocating)
  // while it does, so it is a re-entry source as well as a victim.
  if (TrackerReentered("HandleProcessExecuteFlagsChange", Flags, 0)) {
    return;
  }
  TrackerLockScope Reentry;
  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  std::unique_lock Lock(IntervalsLock);

  if (DisableDEP == DEPDisabled) {
    return;
  }

  DEPDisabled = DisableDEP;

  if (DisableDEP) {
    DEPPromotedIntervals.Clear();

    MEMORY_BASIC_INFORMATION Info;
    uint64_t Address = 0;

    while (VirtualQuery(reinterpret_cast<LPCVOID>(Address), &Info, sizeof(Info))) {
      uint64_t BaseAddress = reinterpret_cast<uint64_t>(Info.BaseAddress);
      if (Info.State == MEM_COMMIT && ProtIsReadable(Info.Protect) && !ProtHasExec(Info.Protect)) {
        const auto AlignedBase = BaseAddress & FEXCore::Utils::FEX_PAGE_MASK;
        const auto AlignedSize = (BaseAddress - AlignedBase + Info.RegionSize + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;
        FEXCore::IntervalList<uint64_t>::Interval ProtInterval {AlignedBase, AlignedBase + AlignedSize};

        XIntervals.Insert(ProtInterval);
        if (ProtIsWritable(Info.Protect)) {
          RWXIntervals.Insert(ProtInterval);
        }
        DEPPromotedIntervals.Insert(ProtInterval);
      }

      Address = BaseAddress + Info.RegionSize;
    }
  } else {
    // ml760: this loop logs and removes (both allocate) with IntervalsLock held exclusively.
    // It cannot self-deadlock any more -- TrackerLockScope above makes every nested
    // notification bail out -- but the log is now rate-capped so a module-heavy process
    // cannot spend an unbounded time inside the exclusive hold.
    uint32_t DepRemoveCount = 0;
    for (const auto& Interval : DEPPromotedIntervals) {
      if (++DepRemoveCount <= 16 || !(DepRemoveCount & 63)) {
        LogMan::Msg::EFmt("[iOS-xrem] via=depflags #{} tracker={} {:#x}-{:#x}", DepRemoveCount, static_cast<void*>(this),
                          Interval.Offset, Interval.End);
      }
      XIntervals.Remove(Interval);
      RWXIntervals.Remove(Interval);
    }
    DEPPromotedIntervals.Clear();
  }

  // Invalidate all cached code: previously-compiled blocks may contain NoExec stubs for addresses
  // that are now executable (or reference regions whose executability just changed).
  InvalidateIntervalInternalLocked(0, std::numeric_limits<uint64_t>::max());
}

void InvalidationTracker::HandleImageMap(std::string_view Name, uint64_t Address) {
  // ml760: reachable from NotifyMapViewOfSection AND from wine's loader via NotifyImageMap,
  // so it must be safe on a thread that is already inside this tracker.
  if (TrackerReentered("HandleImageMap", Address, 0)) {
    return;
  }

  auto* Nt = RtlImageNtHeader(reinterpret_cast<HMODULE>(Address));
  auto* SectionsBegin = IMAGE_FIRST_SECTION(Nt);
  auto* SectionsEnd = SectionsBegin + Nt->FileHeader.NumberOfSections;
  uint64_t LastExecutableSectionEnd = 0;

  /* iOS-Madeira ml760: ONE LOCK FOR THE WHOLE IMAGE, AND NO LOGGING UNDER IT.
   *
   * The previous shape took std::unique_lock(IntervalsLock) INSIDE the per-section loop and
   * ran both XIntervals.Insert and the [iOS-xins] EFmt with it held. Both allocate, and an
   * allocator growth re-enters HandleMemoryProtectionNotification, which takes the same
   * non-recursive shared_mutex -- the hang described at the top of this file.
   *
   * Three changes, in order of importance:
   *   1. the re-entrancy guard (TrackerLockScope) makes a nested notification bail out;
   *   2. the section ranges are collected into a FIXED-SIZE STACK array first, so nothing
   *      inside the locked region allocates except the interval vectors themselves;
   *   3. the log lines are emitted AFTER the lock is released, so formatting allocations can
   *      never happen under it at all.
   * Sections are processed in batches of the array size, so an image with more executable
   * sections than the array holds simply takes more than one lock/log round -- nothing is
   * dropped and the stack cost stays bounded (PE NumberOfSections is a uint16). */
  struct ExecSection {
    uint64_t Base;
    uint64_t End;
    bool Writable;
  };

  for (auto* Section = SectionsBegin; Section != SectionsEnd;) {
    ExecSection Batch[32];
    unsigned Count = 0;

    for (; Section != SectionsEnd && Count < std::size(Batch); Section++) {
      if (!(Section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
        continue;
      }
      const uint64_t SectionBase = Address + Section->VirtualAddress;
      const uint64_t SectionEnd = SectionBase + Section->Misc.VirtualSize;
      LastExecutableSectionEnd = std::max(LastExecutableSectionEnd, SectionEnd);
      Batch[Count++] = {SectionBase, SectionEnd, (Section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0};
    }

    if (!Count) {
      continue;
    }

    {
      TrackerLockScope Reentry;
      std::unique_lock Lock(IntervalsLock);
      for (unsigned i = 0; i < Count; i++) {
        XIntervals.Insert({Batch[i].Base, Batch[i].End});
        if (Batch[i].Writable) {
          RWXIntervals.Insert({Batch[i].Base, Batch[i].End});
        }
      }
    }

    /* iOS-Madeira ml200: FEX reports NOEXEC for code addresses even though the ntdll side
     * proves the map notification arrives and nothing ever removes the interval. So log the
     * actual inserts (with `this`, since each pseudo-process runs its own xtajit64 copy and
     * its own tracker) and pair it with the query-side log in QueryGuestExecutableRange. If
     * the insert and the failing query name different `this`, the registration is landing in
     * a different process's tracker.
     * ml760: printed after the lock is dropped -- the insert has already happened, so the
     * line still means "this range IS registered". */
    for (unsigned i = 0; i < Count; i++) {
      LogMan::Msg::EFmt("[iOS-xins] tracker={} {} sec={:#x}-{:#x}", static_cast<void*>(this), Name, Batch[i].Base, Batch[i].End);
      if (Batch[i].Writable) {
        LogMan::Msg::DFmt("Add image SMC interval: {:X} - {:X}", Batch[i].Base, Batch[i].End);
      }
    }
  }

  FEX_CONFIG_OPT(MonoHacks, MONOHACKS);
  FEX_CONFIG_OPT(MaxInst, MAXINST);
  FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);

  /* ml712: wine-mono ships its runtime as libmono-2.0-x86_64.dll (the file mscoree's
   * find_mono_dll() looks for on an x86_64/ARM64EC host), which matched neither name
   * above -- so on Marvel Cosmic Invasion the hooks stayed inert and Mono startup paid
   * the full W^X tax: ~735,000 emulated stores from one hot site during init.
   *
   * Recognised, but activation is OPT-IN via MADEIRA_WINEMONO_BRIDGE=1, default OFF, for a
   * correctness reason rather than caution about perf: the bridge reclassifies a detected
   * XCHG from a true atomic exchange into an alias-directed plain write. Deciding that by
   * FILENAME alone would let any unrelated lock-free XCHG in this DLL be treated as a
   * backpatch site and silently lose its atomicity -- and wine-mono's thread-suspend
   * machinery is exactly the kind of lock-free code that would break. The existing two
   * names are Unity's embedded Mono, where the hook has been field-proven since ml648.
   *
   * Verification is deliberately incomplete: wine-mono ships no PDB (its debug directory
   * points at a build-server path) and its exports are ~195KB apart around the hot RIP, so
   * the faulting site CANNOT be symbolized offline to prove it is a code-patching routine.
   * Until it is, this stays off by default and the detected RIP is logged for inspection.
   *
   * NOTE: this storm is a STARTUP cost and is NOT why the game shows no window. Measured
   * between matched checkpoints the rate is ~91/sec by the time FNA3D loads, not the
   * thousands/sec a cumulative-total-over-runtime average suggests. The current stall is
   * thread 007c holding a Mono critical section while workers queue behind it. */
  const bool IsUnityMono = (Name == "mono-2.0-bdwgc.dll" || Name == "mono.dll");
  const bool IsWineMono = (Name == "libmono-2.0-x86_64.dll" || Name == "libmono-2.0-x86.dll");
  bool WineMonoOptIn = false;
  if (IsWineMono) {
    const char* Env = getenv("MADEIRA_WINEMONO_BRIDGE");
    WineMonoOptIn = Env && Env[0] == '1';
    LogMan::Msg::EFmt("[mono-winemono] ml712 module={} base={:#x} opt-in={} (MADEIRA_WINEMONO_BRIDGE={})", Name, Address,
                      WineMonoOptIn ? 1 : 0, Env ? Env : "unset");
  }

  const bool IsMono = IsUnityMono || (IsWineMono && WineMonoOptIn);
  if (IsMono) {
    /* ml623: report the EFFECTIVE settings at EFmt on every branch.
     *
     * MonoHacks defaults to true and is gated on Multiblock && MaxInst >= 500, but
     * MarkMonoDetected() logs nothing and the refusal message is IFmt, which
     * MADEIRA_QUIET eats -- so the ULTRAKILL log could not distinguish "hooks armed"
     * from "hooks refused". That ambiguity also decides whether a later
     * block-splitting A/B is interpretable at all, because the hook explicitly
     * requires all SMC sites to land in ONE block. Never leave this unfalsifiable. */
    const bool Armed = MonoHacks && Multiblock && MaxInst() >= 500;
    LogMan::Msg::EFmt("[mono-cfg] ml623 module={} base={:#x} xend={:#x} | MonoHacks={} Multiblock={} MaxInst={} => {}", Name,
                      Address, LastExecutableSectionEnd, MonoHacks() ? 1 : 0, Multiblock() ? 1 : 0, MaxInst(),
                      Armed          ? "HOOKS ARMED (MarkMonoDetected)" :
                      !MonoHacks()   ? "off: MonoHacks disabled" :
                                       "off: needs Multiblock && MaxInst>=500");
    if (Armed) {
      // Require these settings to ensure we can safely hook all SMC sites in a single block
      CTX.MarkMonoDetected();
      MonoBackpatcherDetectionPending = true;
      MonoBase = Address;
      MonoEnd = LastExecutableSectionEnd;
#ifdef FEX_IOS_HOST
      /* ml648: arm the native bridge HERE, not at FEX startup — Mono is not
       * loaded then. The Mach handler declines to capture while mono_base is 0,
       * so the ordering is enforced by construction rather than by discipline.
       * This is the last of the three one-time liveness lines; without it a run
       * with no activations cannot be told apart from one where the bridge was
       * never wired up at all. */
      ios_fex_mono_arm(MonoBase, MonoEnd);
#endif
    }
  }

  /* ml623: arm the targeted IR capture (PassManager.cpp) once the module that owns the
   * instruction under investigation is mapped. Module + RVA come from the environment so
   * chasing a different miscompile never needs a rebuild; the defaults are the ULTRAKILL
   * Mono emitter store `mov byte ptr [rcx+2], al`.
   *
   * setenv() in WineProcessBridge.m does NOT reach GetEnvironmentVariableW, but it DOES
   * reach FEX's own getenv (proven by MADEIRA_NO_DFE in ml597/598), which is what this uses. */
  {
    const char* CapRVA = getenv("MADEIRA_IRCAP_RVA");
    const char* CapMod = getenv("MADEIRA_IRCAP_MODULE");

    /* ml623b: THE ENV CHANNEL DOES NOT REACH THIS CODE.
     *
     * ml623 shipped env-gated and never armed -- yet [mono-cfg] printed from this very
     * function in the same run, so the function ran and getenv simply returned null.
     * (get_initial_environment copies all of unix `environ` into the Windows block, so
     * the loss is somewhere later: the PE CRT's copy, or the pseudo-process PEB clone.)
     * Rather than theorise, the target is now COMPILED IN and env is only an override.
     * The probe line below reports what getenv actually returned, so the channel
     * question gets settled for free instead of costing another run. */
    {
      static bool Reported = false;
      if (!Reported) {
        Reported = true;
        LogMan::Msg::EFmt("[ircap] ml623b env probe: MADEIRA_IRCAP_RVA={} MADEIRA_IRCAP_MODULE={}", CapRVA ? CapRVA : "(null)",
                          CapMod ? CapMod : "(null)");
      }
    }
    if (!CapRVA || !*CapRVA) {
      CapRVA = "0x4db25b"; // mono-2.0-bdwgc.dll: mov byte ptr [rcx+2], al
    }
    if (CapRVA && *CapRVA) {
      if (!CapMod || !*CapMod) {
        CapMod = "mono-2.0-bdwgc.dll";
      }
      // Case-insensitive: the loader logs both "VERSION.dll" and "version.dll".
      const size_t ModLen = strlen(CapMod);
      bool Match = (Name.size() == ModLen);
      for (size_t i = 0; Match && i < ModLen; ++i) {
        const char A = Name[i] | 0x20;
        const char B = CapMod[i] | 0x20;
        Match = (A == B);
      }
      if (Match) {
        const uint64_t RVA = strtoull(CapRVA, nullptr, 0);
        if (RVA) {
          FEX_MadeiraIRCapTarget = Address + RVA;
          LogMan::Msg::EFmt("[ircap] ml623b ARMED: module={} base={:#x} rva={:#x} => target guest addr {:#x}", Name, Address,
                            RVA, FEX_MadeiraIRCapTarget);
        } else {
          LogMan::Msg::EFmt("[ircap] ml623b DISARMED by MADEIRA_IRCAP_RVA=0 (module={})", Name);
        }
      }
    }
  }
}

InvalidationTracker::InvalidateContainingSectionResult InvalidationTracker::InvalidateContainingSection(uint64_t Address, bool Free) {
  // ml760: reached from NotifyUnmapViewOfSection; takes both locks below.
  if (TrackerReentered("InvalidateContainingSection", Address, 0)) {
    return {Address, 0};
  }

  MEMORY_BASIC_INFORMATION Info;
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
    return {Address, 0};
  }

  const auto SectionBase = reinterpret_cast<uint64_t>(Info.AllocationBase);
  auto SectionSize = reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize - SectionBase;

  while (!NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(SectionBase + SectionSize), MemoryBasicInformation, &Info,
                               sizeof(Info), nullptr) &&
         reinterpret_cast<uint64_t>(Info.AllocationBase) == SectionBase) {
    SectionSize += Info.RegionSize;
  }

  InvalidateIntervalInternal(SectionBase, SectionSize);

  if (Free) {
    {
      // ml760: remove under the lock, log after releasing it -- EFmt allocates.
      TrackerLockScope Reentry;
      std::unique_lock Lock(IntervalsLock);
      XIntervals.Remove({SectionBase, SectionBase + SectionSize});
      RWXIntervals.Remove({SectionBase, SectionBase + SectionSize});
    }
    LogMan::Msg::EFmt("[iOS-xrem] via=section tracker={} {:#x}-{:#x}", static_cast<void*>(this),
                      SectionBase, SectionBase + SectionSize);
  }

  return {SectionBase, SectionSize};
}

void InvalidationTracker::InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free) {
  // ml760: reached from NotifyMemoryFree; takes CodeInvalidationMutex and IntervalsLock below.
  if (TrackerReentered("InvalidateAlignedInterval", Address, Size)) {
    return;
  }

  if (!Address) {
    // Match the Windows behaviour when passed a NULL base address.
    Size = std::numeric_limits<uint64_t>::max();
  }

  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = std::max(Size, (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK);

  InvalidateIntervalInternal(AlignedBase, AlignedSize);

  if (Free) {
    {
      // ml760: remove under the lock, report after releasing it.
      TrackerLockScope Reentry;
      std::unique_lock Lock(IntervalsLock);
      XIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
      RWXIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
    }
    // ml437 (#74): this fires on EVERY guest free/decommit (the ml201 probe is
    // unconditional) — ml436 logged 4,234 lines of ordinary heap decommit
    // churn, drowning the log and costing a dprintf syscall per free. The
    // signal (which path removes a tracked range) is preserved by the first 40
    // plus a 1-in-64 sample.
    static std::atomic<uint32_t> AlignedRemoveCount;
    const auto N = AlignedRemoveCount.fetch_add(1) + 1;
    if (N <= 40 || !(N & 63)) {
      LogMan::Msg::EFmt("[iOS-xrem] via=aligned #{} tracker={} {:#x}-{:#x}", N, static_cast<void*>(this),
                        AlignedBase, AlignedBase + AlignedSize);
    }
  }
}

void InvalidationTracker::ReprotectRWXIntervals(uint64_t Address, uint64_t Size) {
  ProtectRWXIntervalsInternal(Address, Size, false);
}

bool InvalidationTracker::HandleRWXAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPc, uint64_t FaultAddress) {
  // ml760: a fault taken while this thread is already inside the tracker cannot be serviced
  // here without re-locking. Decline it -- the caller then treats it as an ordinary AV --
  // rather than park the thread forever.
  if (TrackerReentered("HandleRWXAccessViolation", FaultAddress, 0)) {
    return false;
  }

  const auto [NeedsInvalidate, UntrapProt] = [&](uint64_t Address) -> std::pair<bool, ULONG> {
    TrackerLockScope Reentry;
    std::shared_lock Lock(IntervalsLock);
    if (!RWXIntervals.Query(Address).Enclosed) {
      return {false, 0};
    }
    return {true, GetUntrapProt(Address)};
  }(FaultAddress);

  if (NeedsInvalidate) {
    // IntervalsLock cannot be held during invalidation
    {
      // ml760: NtProtectVirtualMemory below re-enters NotifyMemoryProtect ->
      // HandleMemoryProtectionNotification, which would take CodeInvalidationMutex again
      // (via InvalidateIntervalInternal) on this very thread. The guard makes that
      // notification bail out; what it skips is the untrap this code just performed and
      // has already accounted for.
      TrackerLockScope Reentry;
      std::scoped_lock Lock(CTX.GetCodeInvalidationMutex());

      InvalidateIntervalInternalLocked(FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE);

      // Invalidate, then unprotect the faulting page with the compilation lock held to ensure that any racing invalidations are not dropped.
      ULONG TmpProt;
      void* TmpAddress = reinterpret_cast<void*>(FaultAddress);
      SIZE_T TmpSize = 1;
      NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, UntrapProt, &TmpProt);
    }
    DetectMonoBackpatcherBlock(Thread, HostPc);
    return true;
  }
  return false;
}

bool InvalidationTracker::BeginUntrackedWriteLocked(uint64_t Address, uint64_t Size) {
  return ProtectRWXIntervalsInternal(Address, Size, true);
}

/* iOS-Madeira ml201: log EVERY XIntervals removal, tagged by path.
 *
 * Proven this run: libcef's .text IS inserted (0x7385cf1000-0x7390d2cd23) into the SAME
 * tracker (0x1229612c8) that later reports MISS for 0x73875f0733 and 0x73898408f0 — both
 * inside that range. IntervalList::Query and ::Insert are correct for a sorted disjoint
 * list, so a sub-range must be getting REMOVED. My ntdll-side probes only covered
 * NtProtectVirtualMemory and unmap; Remove is also reachable from
 * HandleProcessExecuteFlagsChange (DEP) and InvalidateAlignedInterval (via
 * NotifyMemoryFree), neither of which was instrumented. Tag each site so the culprit
 * path names itself. */
FEXCore::HLE::ExecutableRangeInfo InvalidationTracker::QueryExecutableRange(uint64_t Address) {
  std::shared_lock Lock(IntervalsLock);
  const auto XResult = XIntervals.Query(Address);
  if (!XResult.Enclosed) {
    return {};
  }
  const auto RWXResult = RWXIntervals.Query(Address);
  if (RWXResult.Enclosed) {
    return {RWXResult.Interval.Offset, RWXResult.Interval.End - RWXResult.Interval.Offset, true};
  } else if (RWXResult.Size && RWXResult.Size < XResult.Size) {
    return {XResult.Interval.Offset, RWXResult.Interval.Offset - XResult.Interval.Offset, false};
  }
  return {XResult.Interval.Offset, XResult.Interval.End - XResult.Interval.Offset, false};
}

void InvalidationTracker::DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPc) {
  if (!MonoBackpatcherDetectionPending) {
    return;
  }

  if (!CTX.IsAddressInCodeBuffer(Thread, HostPc)) {
    return;
  }

  // MADEIRA: RestoreRIPFromHostPC returns a GUEST rip, while MonoBase/MonoEnd come from
  // HandleImageMap and are therefore HOST addresses (see the namespace note in the header). Lift
  // the RIP into the host namespace for the module-range test and for the code reads below; the
  // BlockEntry used further down stays guest, because it is a FEXCore invalidation key.
  const uint64_t GuestRIP = CTX.RestoreRIPFromHostPC(Thread, HostPc);
  const uint64_t RIP = GuestRIP ? GuestRIP + GuestBase : 0;
  if (!RIP || RIP < MonoBase || RIP >= MonoEnd) {
    return;
  }

  static constexpr uint8_t XChgOp = 0x87;
  if (*reinterpret_cast<uint8_t*>(RIP) != XChgOp && *reinterpret_cast<uint8_t*>(RIP + 1) != XChgOp) {
    return;
  }

  uint64_t BlockEntry = CTX.GetGuestBlockEntry(Thread);
  LogMan::Msg::DFmt("Detected mono backpatcher at: {:X}", BlockEntry);

  /* ml712: name the site at EFmt, once, with module-relative RVAs and the bytes.
   *
   * The DFmt line above is eaten by MADEIRA_QUIET, so a run could neither confirm which
   * guest instruction was reclassified nor let it be checked afterwards. That matters more
   * for wine-mono than for Unity's Mono: this reclassifies an XCHG from a true atomic
   * exchange into an alias-directed plain write, wine-mono ships no PDB, and its exports
   * sit ~195KB apart around the hot region -- so the RVA printed here is the ONLY evidence
   * available for deciding whether the site is a genuine code-patching routine or an
   * unrelated lock-free exchange that must keep its atomicity. Print it before marking. */
  {
    static bool Reported = false;
    if (!Reported) {
      Reported = true;
      const auto* Bytes = reinterpret_cast<const uint8_t*>(RIP);
      // MADEIRA: BlockEntry is guest, MonoBase is host, so lift the block entry for the RVA.
      LogMan::Msg::EFmt("[mono-site] ml712 FIRST detect rip={:#x} (mono+{:#x}) block={:#x} (mono+{:#x}) "
                        "bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                        RIP, RIP - MonoBase, BlockEntry, BlockEntry + GuestBase - MonoBase, Bytes[0], Bytes[1], Bytes[2],
                        Bytes[3], Bytes[4], Bytes[5], Bytes[6], Bytes[7]);
    }
  }
#ifndef FEX_IOS_HOST
  /* ml648: SKIPPED ON iOS. DisableSMCDetection() reprotects every RWX interval
   * as WRITABLE, and iOS will never grant write on the guest VA — that is the
   * entire reason the RW alias exists. On iOS it can only churn protections
   * that cannot change. The win here comes purely from MarkMonoBackpatcherBlock
   * plus the alias-directed MonoBackpatcherWrite. */
  DisableSMCDetection();
#endif
  {
    std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
    CTX.MarkMonoBackpatcherBlock(BlockEntry);
  }
  // MADEIRA: InvalidateAlignedInterval takes host addresses like the rest of this class.
  InvalidateAlignedInterval(BlockEntry + GuestBase, FEXCore::Utils::FEX_PAGE_SIZE, false);
}

void InvalidationTracker::DisableSMCDetection() {
  // ml760: NtProtectVirtualMemory is called inside this exclusive hold, and its
  // NotifyMemoryProtect callback lands back in HandleMemoryProtectionNotification.
  TrackerLockScope Reentry;
  std::unique_lock Lock(IntervalsLock);
  SMCDetectionDisabled = true;
  uint64_t Address = 0;

  // Reprotect all RWX intervals as writable
  FEXCore::IntervalList<uint64_t>::QueryResult Query;
  do {
    Query = RWXIntervals.Query(Address);
    if (Query.Enclosed) {
      void* TmpAddress = reinterpret_cast<void*>(Address);
      SIZE_T TmpSize = static_cast<SIZE_T>(Query.Size);
      ULONG TmpProt;
      NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, GetUntrapProt(Address), &TmpProt);
    }
    Address += Query.Size;
  } while (Query.Size);
}

ULONG InvalidationTracker::GetTrapProt(uint64_t Address) const {
  if (DEPDisabled && DEPPromotedIntervals.Query(Address).Enclosed) {
    return PAGE_READONLY;
  }
  return PAGE_EXECUTE_READ;
}

ULONG InvalidationTracker::GetUntrapProt(uint64_t Address) const {
  if (DEPDisabled && DEPPromotedIntervals.Query(Address).Enclosed) {
    return PAGE_READWRITE;
  }
  return PAGE_EXECUTE_READWRITE;
}

void InvalidationTracker::InvalidateIntervalInternal(uint64_t Address, uint64_t Size) {
  // ml760: CodeInvalidationMutex is a WritePriorityMutex and is no more recursive than
  // IntervalsLock. Invalidation allocates (code buffers, per-thread caches), so the same
  // allocator re-entry that deadlocks IntervalsLock deadlocks this one too.
  TrackerLockScope Reentry;
  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  InvalidateIntervalInternalLocked(Address, Size);
}

void InvalidationTracker::InvalidateIntervalInternalLocked(uint64_t Address, uint64_t Size) {
  // NOTE: This assumes CodeInvalidationMutex is locked by the caller
  //
  // MADEIRA: this is the boundary. `Address` is a host address (see the namespace note in the
  // header); FEXCore's code buffers and per-thread lookup caches are keyed on guest addresses, so
  // convert here. A host address outside the window has no guest counterpart and cannot name guest
  // code, so there is nothing to invalidate - this is how the FEX code pool's own addresses, which
  // also flow through the BTCpuNotifyMemory* callbacks, get filtered out.
  if (GuestBase) {
    if (Address < GuestBase || (Address - GuestBase) >= (1ULL << 32)) {
      return;
    }
    Address -= GuestBase;
  }

  CTX.InvalidateCodeBuffersCodeRange(Address, Size);
  for (auto Thread : Threads) {
    CTX.InvalidateThreadCachedCodeRange(Thread.second, Address, Size);
  }
}

bool InvalidationTracker::ProtectRWXIntervalsInternal(uint64_t Address, uint64_t Size, bool ForWriteLocked) {
  const auto End = Address + Size;
  // ml760: NtProtectVirtualMemory runs inside this SHARED hold. Its NotifyMemoryProtect
  // callback wants IntervalsLock EXCLUSIVELY on this same thread, and std::shared_mutex has
  // no shared->exclusive upgrade, so without the guard this is a self-deadlock too.
  TrackerLockScope Reentry;
  std::shared_lock Lock(IntervalsLock);

  if (SMCDetectionDisabled) {
    return false;
  }

  bool HitRWXInterval = false;
  do {
    const auto Query = RWXIntervals.Query(Address);
    if (Query.Enclosed) {
      if (!HitRWXInterval) {
        if (ForWriteLocked) {
          // If we are protecting as writable, then the entire range must be invalidated before any protections are
          // applied and the invalidation mutex must be locked throughout.
          // Do this lazily only when an RWX region is actually hit.
          // NOTE: This assumes CodeInvalidationMutex is locked by the caller
          InvalidateIntervalInternalLocked(Address, Size);
        }
        HitRWXInterval = true;
      }
      void* TmpAddress = reinterpret_cast<void*>(Address);
      SIZE_T TmpSize = static_cast<SIZE_T>(std::min(End, Address + Query.Size) - Address);
      ULONG TmpProt;
      NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, ForWriteLocked ? GetUntrapProt(Address) : GetTrapProt(Address), &TmpProt);
    } else if (!Query.Size) {
      // No more regions past `Address` in the interval list
      break;
    }

    Address += Query.Size;
  } while (Address < End);

  return HitRWXInterval;
}

} // namespace FEX::Windows
