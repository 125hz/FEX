// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/Context.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Debug/InternalThreadState.h>

/* iOS-Madeira ml706: the one VA-layout profile, selected in rpmalloc's os_mmap
 * (the earliest allocator in the process) and followed here. C linkage: it is
 * chosen from C. */
extern "C" {
extern uintptr_t ios_fex_band_base;
extern uintptr_t ios_fex_band_end;
/* MADEIRA ml708: the dual-mapped JIT pool's RX range, defined next to the band in rpmalloc.c and
 * published by the CPU module at process init. Zero until then. */
extern uintptr_t ios_fex_jit_pool_rx;
extern uintptr_t ios_fex_jit_pool_end;
}

namespace FEX::Windows::CallRetStack {
struct CallRetStackInfo {
  uint64_t AllocationBase;
  uint64_t AllocationEnd;
  uint64_t DefaultLocation;
};

CallRetStackInfo GetInfoThread(FEXCore::Core::InternalThreadState* Thread) {
  uint64_t Base = reinterpret_cast<uint64_t>(Thread->CallRetStackBase);
  // Leave some room from the base for the default location to allow for underflows without constant exceptions
  return {Base - FEXCore::Utils::FEX_PAGE_SIZE, Base + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + FEXCore::Utils::FEX_PAGE_SIZE,
          Base + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4};
}

/* Returns false if the call-ret stack could not be placed.
 *
 * This region has no unconstrained fallback ON PURPOSE (see below), so failure
 * is a real outcome, not a theoretical one -- a title that creates enough
 * threads exhausts the band and the 37th thread gets nothing. Previously the
 * nullptr was carried straight into arithmetic: base + one guard page = 0x1000,
 * dereferenced immediately, and the resulting fault recursed through the
 * exception path until the thread's stack was gone. The thread then died
 * OWNING wine's loader_section, so the next module load blocked forever and the
 * process sat inert with no error anywhere. Report it and let the caller
 * unwind. */
#ifdef FEX_IOS_HOST
/* Deterministic failure injection for the call-ret stack, default OFF.
 *
 *   MADEIRA_FEX_FAIL_CALLRET=reserve:N   fail the Nth reservation
 *   MADEIRA_FEX_FAIL_CALLRET=commit:N    let the Nth reservation succeed, then
 *                                        fail its commit
 *
 * Both paths exist in the field -- a title that creates enough threads
 * exhausts the band -- but only the reserve path reproduces naturally, and a
 * containment path that has never executed is an assumption. One-shot and
 * counted, so a single run exercises exactly one failure and everything after
 * it proceeds normally, which is what proves the process SURVIVES rather than
 * merely fails. */
enum class CallRetInject { None, Reserve, Commit, ThreadState };

static CallRetInject GetInjectMode(unsigned& TargetOut) {
  static CallRetInject Mode = CallRetInject::None;
  static unsigned Target = 0;
  static std::once_flag Once;
  std::call_once(Once, [] {
    const char* Env = getenv("MADEIRA_FEX_FAIL_CALLRET");
    if (!Env) return;
    const char* Colon = strchr(Env, ':');
    if (!Colon) return;
    Target = (unsigned)atoi(Colon + 1);
    if (!Target) return;
    if (!strncmp(Env, "reserve:", 8)) Mode = CallRetInject::Reserve;
    else if (!strncmp(Env, "commit:", 7)) Mode = CallRetInject::Commit;
    else if (!strncmp(Env, "threadstate:", 12)) Mode = CallRetInject::ThreadState;
    if (Mode != CallRetInject::None) {
      LogMan::Msg::EFmt("[callret] INJECTION ARMED: {} -- will fail call #{}", Env, Target);
    }
  });
  TargetOut = Target;
  return Mode;
}
#endif

bool InitializeThread(FEXCore::Core::InternalThreadState* Thread) {
#ifdef FEX_IOS_HOST
  unsigned InjectTarget = 0;
  const CallRetInject InjectMode = GetInjectMode(InjectTarget);
  static std::atomic<unsigned> CallCount {0};
  const unsigned ThisCall = ++CallCount;
  const bool InjectReserve = (InjectMode == CallRetInject::Reserve && ThisCall == InjectTarget);
  const bool InjectCommit  = (InjectMode == CallRetInject::Commit  && ThisCall == InjectTarget);
#endif

  // Allocate the call-ret stack with guard pages on both sides
  const size_t CallRetStackAllocSize = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * FEXCore::Utils::FEX_PAGE_SIZE;
  const void* CallRetStackAlloc = nullptr;
#ifdef FEX_IOS_HOST
  /* iOS-Madeira ml324: steer the call-ret stack out of the guest VA band.
   *
   * This calls ::VirtualAlloc directly rather than FEXCore::Allocator::VirtualAlloc,
   * so ml321's steering missed it -- ml323 confirmed every other FEXMem_* region moved
   * to 0x74xx while FEXMem_CallRetStacks stayed at 0x73dx, interleaved with guest
   * allocations. This is the worst region to leave there: each 16-byte frame holds a
   * HOST code label (the intra-block adr(&l_CallReturn)), so a guest over-read lands on
   * exactly the kind of value that has been showing up as a bogus branch target
   * ("loaded from guest memory", ml316). Same window and same fallback discipline as
   * AllocatorHooks.h -- see the ml325 correction there for why the band must stay
   * clear of [0x7400000000, 0x7c00000000) (CEF's four 16GB PartitionAlloc pools). */
  {
    MEM_ADDRESS_REQUIREMENTS AddrReq {};
    MEM_EXTENDED_PARAMETER AddrParam {};
    /* ml706: follow the band rpmalloc selected, do not hardcode it. */
    AddrReq.LowestStartingAddress = reinterpret_cast<void*>(ios_fex_band_base);
    AddrReq.HighestEndingAddress = reinterpret_cast<void*>(ios_fex_band_end);
    AddrParam.Type = MemExtendedParameterAddressRequirements;
    AddrParam.Pointer = &AddrReq;
      if (InjectReserve) {
        LogMan::Msg::EFmt("[callret] INJECTED reserve failure on call #{} -- taking the real "
                          "containment path", ThisCall);
      } else if (ios_fex_band_base) {
      CallRetStackAlloc = ::VirtualAlloc2(nullptr, nullptr, CallRetStackAllocSize, MEM_RESERVE, PAGE_NOACCESS, &AddrParam, 1);
    }
  }
  /* ml706: NO unconstrained fallback here. Each 16-byte frame holds a HOST
   * code label, so a guest over-read yields exactly the bogus branch targets
   * of ml316 -- guest-band placement is worse than failing outright. */
#else
  if (!CallRetStackAlloc) {
    CallRetStackAlloc = ::VirtualAlloc(nullptr, CallRetStackAllocSize, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
  }
#endif

  if (!CallRetStackAlloc) {
    /* No unconstrained fallback exists here BY DESIGN (see above), so this is
     * a real outcome once the band fills: a title that creates enough threads
     * exhausts it and a later thread gets nothing. Carrying the nullptr on
     * meant base + one guard page = 0x1000, dereferenced at once, and the
     * fault recursed until the stack was gone -- with the thread still owning
     * the loader lock. */
    LogMan::Msg::EFmt("[callret] RESERVE FAILED: {:#x} bytes in band [{:#x},{:#x}] -- thread cannot start",
                      (unsigned long long)CallRetStackAllocSize,
                      (unsigned long long)ios_fex_band_base, (unsigned long long)ios_fex_band_end);
    return false;
  }

  FEXCore::Allocator::VirtualName("FEXMem_CallRetStacks", CallRetStackAlloc,
                                  FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * FEXCore::Utils::FEX_PAGE_SIZE);
  FEXCore::Allocator::VirtualTHPControl(CallRetStackAlloc, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * FEXCore::Utils::FEX_PAGE_SIZE,
                                        FEXCore::Allocator::THPControl::Disable);

  Thread->CallRetStackBase = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(CallRetStackAlloc) + FEXCore::Utils::FEX_PAGE_SIZE);
  /* The COMMIT can fail on its own: the reservation only claims addresses.
   * Hand the reservation back rather than leaking a 16MB hole in a band that
   * is already too small to satisfy the next thread. */
#ifdef FEX_IOS_HOST
  if (InjectCommit) {
    LogMan::Msg::EFmt("[callret] INJECTED commit failure on call #{} -- the reservation succeeded "
                      "and must now be released", ThisCall);
  }
#endif
  if (
#ifdef FEX_IOS_HOST
      InjectCommit ||
#endif
      !::VirtualAlloc(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE, MEM_COMMIT,
                      PAGE_READWRITE)) {
    LogMan::Msg::EFmt("[callret] COMMIT FAILED: {:#x} bytes at {} -- releasing the reservation",
                      (unsigned long long)FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE,
                      Thread->CallRetStackBase);
    ::VirtualFree(const_cast<void*>(CallRetStackAlloc), 0, MEM_RELEASE);
    Thread->CallRetStackBase = nullptr;
    return false;
  }

  /* iOS-Madeira: VirtualAlloc(MEM_COMMIT) on a previously-MEM_RESERVE'd
   * PAGE_NOACCESS region might not zero-initialize the pages on iOS. The
   * dispatcher uses callret_sp to BLR via stored values; uninit content
   * (e.g. 0x55 poison from prior wine activity) would BLR to garbage.
   * ml362: the unconditional memset committed the full 16MB as private-dirty
   * per thread (~670MB at 40 threads, ml361 [phys-map] showed these regions
   * fully dirty). ZeroScrub keeps the zero guarantee but only dirties pages
   * that actually hold stale bytes; the stale count is the probe for whether
   * wine's commit really hands back nonzero pages.
   *
   * ml900: ZeroScrub WAS THE COST IT WAS WRITTEN TO AVOID. Its premise -- "reading an
   * untouched anonymous page maps the shared zero page, no footprint" -- is a LINUX fact.
   * Darwin has no shared zero page for anonymous memory: a READ fault on an absent page of
   * an internal VM object allocates a real zero-filled page into that object, and internal
   * pages are charged to phys_footprint whether or not they are ever written. So the scan
   * materialised all 16MB per thread exactly as the memset did.
   *
   * Measured, madeira-log 26 (391s, 32-bit D3D9 title, 36 guest threads):
   *   - [dc-census] on a callret arena: `mincore_res 16384KB -> 32KB` -- the FULL 16MB was
   *     resident before the reset, while `dirty` was only 10448KB. Every page resident but
   *     only some written is the signature of a read-fault sweep, not of use.
   *   - [phys-map] top-12 regions: 10 of them are 0x1004000-sized FEXMem_CallRetStacks at
   *     14-16MB charged each, most of it `swap=` (compressed), i.e. zero pages the
   *     compressor is paying to hold.
   *   - EmitCallRetStackGuard bounds callret_sp to a 4MB window and [callret-gen] reported
   *     ONE reset in the whole run, so use cannot explain a 16MB working set.
   *   - Every [callret] line in the run reported stale=0x0, on every thread: wine's commit
   *     always hands back zeroed pages here, so the memset the scan protects never ran.
   *
   * The right primitive for "make this range zero" on a host with a compressor is to hand
   * the pages back, not to touch them. VirtualDontNeed() is MEM_DECOMMIT + MEM_COMMIT, and
   * wine's decommit_pages() does anon_mmap_fixed() on this (non-pool-aliased) range -- a
   * fresh MAP_ANON|MAP_FIXED that drops the physical pages and installs zero-fill-on-demand.
   * That is a STRONGER guarantee than the scan (all pages are definitely zero, not just the
   * ones a probe looked at) for ZERO footprint, and [dc-census] measures it at 38-251us.
   * It is the same call ResetCallRetStack() already uses on this exact range. */
#ifdef FEX_IOS_HOST
  {
    FEXCore::Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
    LogMan::Msg::EFmt("[callret] zero-by-decommit rev=ml900 base={:#x} size={:#x} (was a full-range read scan, "
                      "which materialised every page on Darwin)",
                      reinterpret_cast<uint64_t>(Thread->CallRetStackBase), FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
  }
#endif

  Thread->CurrentFrame->State.callret_sp = GetInfoThread(Thread).DefaultLocation;
  // iOS-Madeira 2026-05-18: mirror CallRetStackBase into CpuStateFrame so JIT
  // code can emit inline bounds checks. Needed because iOS Wine doesn't honor
  // PAGE_NOACCESS on the guard pages, so the SEH-driven HandleAccessViolation
  // never fires — JIT code has to detect-and-reset proactively.
  Thread->CurrentFrame->State.callret_sp_base = reinterpret_cast<uint64_t>(Thread->CallRetStackBase);

#ifdef FEX_IOS_HOST
  /* iOS-Madeira ml263: print the geometry ONCE per process. Two jobs:
   * (1) a verifiable content marker for the JIT-side guard change in BranchOps.cpp
   *     (an emitter constant leaves no string in the binary, so there is otherwise
   *     nothing to grep in the installed bundle);
   * (2) states the window the inline guard now enforces, so a [callret] dump in a
   *     later crash can be read against it without re-deriving the arithmetic. */
  {
    static bool reported = false;
    if (!reported) {
      reported = true;
      auto Info = GetInfoThread(Thread);
      LogMan::Msg::EFmt("[callret-geom] base={:#x} default={:#x} size={:#x} "
                        "guard-window=[base+0x200000, base+0x600000) grows-DOWN",
                        reinterpret_cast<uint64_t>(Thread->CallRetStackBase), Info.DefaultLocation,
                        FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
      /* iOS-Madeira ml271: print the REAL CpuStateFrame offsets once.
       *
       * The ntdll-unix side reads these fields out of x28 in signal handlers using
       * hand-derived constants, and ml271 showed why that is unsafe: [rsp-forensics]
       * reported gregs[RSP]=0 using a GUESSED 0x28, when RSP is gregs[4] (0x20 into
       * gregs) and gregs itself is not at 0. A wrong offset reads a neighbouring field
       * and invents a bug. Emit the authoritative values so the unix-side probes can be
       * checked against them instead of re-derived by hand. */
      LogMan::Msg::EFmt("[state-offsets] rip={:#x} gregs={:#x} gregs[RSP]={:#x} "
                        "callret_sp={:#x} callret_sp_base={:#x} flags={:#x} sizeof(CPUState)={:#x}",
                        offsetof(FEXCore::Core::CpuStateFrame, State.rip),
                        offsetof(FEXCore::Core::CpuStateFrame, State.gregs),
                        offsetof(FEXCore::Core::CpuStateFrame, State.gregs[FEXCore::X86State::REG_RSP]),
                        offsetof(FEXCore::Core::CpuStateFrame, State.callret_sp),
                        offsetof(FEXCore::Core::CpuStateFrame, State.callret_sp_base),
                        offsetof(FEXCore::Core::CpuStateFrame, State.flags),
                        sizeof(FEXCore::Core::CPUState));
    }
  }
#endif

  return true;
}

void DestroyThread(FEXCore::Core::InternalThreadState* Thread) {
  auto CallRetStackInfo = GetInfoThread(Thread);
  ::VirtualFree(reinterpret_cast<void*>(CallRetStackInfo.AllocationBase), 0, MEM_RELEASE);
}

/* MADEIRA ml708: reject non-pool host targets on the reset path. Every 16-byte callret frame is
 * {guest_rip, host_code_ptr} and the host half is a raw branch target, so a frame whose host half
 * is outside the dual-mapped JIT pool can only ever be wrong -- a sub-4GB or in-guest-window value
 * is a GUEST address, and branching to one executes at `rip` instead of `GuestBase + rip`. A reset
 * exposes whatever bytes sit at DefaultLocation, which after an underflow into a neighbouring
 * mapping need never have been a callret frame at all. Zeroing a rejected frame is safe and
 * sufficient: {0, 0} can never satisfy BranchOps' popped-rip compare, so the RET falls through to
 * the L1 lookup instead of branching. Shared by both reset paths; see the twin in Core.cpp. */
inline void RejectNonPoolTargets(uint64_t DefaultLocation) {
  if (!ios_fex_jit_pool_rx || !ios_fex_jit_pool_end) {
    // Pool bounds not published yet; nothing can be judged, so judge nothing.
    return;
  }
  static volatile uint32_t RejectCount = 0;
  for (int i = 0; i < 4; ++i) {
    uint64_t* Entry = reinterpret_cast<uint64_t*>(DefaultLocation + i * 0x10);
    const uint64_t EntryRip = Entry[0];
    const uint64_t EntryHost = Entry[1];
    if (!EntryRip && !EntryHost) {
      continue;
    }
    if (EntryHost >= ios_fex_jit_pool_rx && EntryHost < ios_fex_jit_pool_end) {
      continue;
    }
    if (__sync_add_and_fetch(&RejectCount, 1) <= 16) {
      LogMan::Msg::EFmt("[callret] rejected non-pool target host=0x{:x} rip=0x{:x}", EntryHost, EntryRip);
    }
    Entry[0] = 0;
    Entry[1] = 0;
  }
}

bool HandleAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t& CallRetSPReg) {
  auto CallRetStackInfo = GetInfoThread(Thread);
  if (Address >= CallRetStackInfo.AllocationBase && Address < CallRetStackInfo.AllocationEnd) {
    LogMan::Msg::DFmt("Call-ret stack inbalance: {:X}", Address);
    RejectNonPoolTargets(CallRetStackInfo.DefaultLocation);
    CallRetSPReg = CallRetStackInfo.DefaultLocation;
    /* Keep State in step with the register the exception context is about to resume with, so a
     * subsequent Fill/Spill of REG_CALLRET_SP cannot resurrect the out-of-bounds value. */
    Thread->CurrentFrame->State.callret_sp = CallRetStackInfo.DefaultLocation;
    return true;
  }
  return false;
}
} // namespace FEX::Windows::CallRetStack
