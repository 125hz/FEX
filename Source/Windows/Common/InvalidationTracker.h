// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <string_view>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::Context {
class Context;
}

namespace FEX::Windows {
/* iOS-Madeira ml2000: true in the ARM64EC module on the iOS host unless MADEIRA_GUEST_RWX_DATA=0.
 * Wine then keeps anonymous x64-guest RWX memory as plain host RW/R data (no JIT-pool alias), so
 * this tracker's protect-on-compile / unprotect-on-write-fault SMC tracking is what keeps code
 * coherent there, at the host's 16 KB page granularity. Always false in the WoW64 module and on
 * non-iOS builds. First call reads the environment and logs once; call it from a normal context
 * first (the constructor does). */
bool IosGuestRwxDataMode();

/**
 * @brief Handles SMC and regular code invalidation
 */
class InvalidationTracker {
public:
  // MADEIRA: address namespace.
  //
  // Every address this class stores, queries and hands to the OS (VirtualQuery,
  // NtQueryVirtualMemory, NtProtectVirtualMemory) is a HOST address, because every one of its
  // callers - wow64.dll's BTCpuNotifyMemory* callbacks, the exception path's fault address, and
  // the image-map notifications - is already speaking host addresses, and because the interval
  // bookkeeping has to line up with what the OS reports.
  //
  // FEXCore, by contrast, keys code invalidation, the lookup caches and executable-range queries
  // on GUEST addresses. The conversion therefore happens at exactly two places:
  //   - inside this class, at the handful of calls into FEXCore (InvalidateIntervalInternalLocked),
  //     using GuestBase below;
  //   - in the WoW64 module's SyscallHandler overrides, which take guest addresses from FEXCore,
  //     add GuestBase on the way in and subtract it from anything returned.
  // That satisfies the design's invariant that the FEXCore <-> InvalidationTracker *boundary* is in
  // the guest namespace, without having to re-express any of the OS-facing logic.
  //
  // GuestBase is 0 for ARM64EC and for every identity-mapped configuration, making all of this a
  // no-op there.
  InvalidationTracker(FEXCore::Context::Context& CTX, const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads,
                      uint64_t GuestBase = 0);

  // Host address of guest address 0, or 0 when identity mapped.
  uint64_t GetGuestBase() const {
    return GuestBase;
  }
  void HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot);
  void HandleProcessExecuteFlagsChange(ULONG Flags);
  void HandleImageMap(std::string_view Name, uint64_t Address);
  struct InvalidateContainingSectionResult {
    uint64_t SectionStart;
    uint64_t SectionSize;
  };
  InvalidateContainingSectionResult InvalidateContainingSection(uint64_t Address, bool Free);
  void InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free);
  void ReprotectRWXIntervals(uint64_t Address, uint64_t Size);
  bool HandleRWXAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC, uint64_t FaultAddress);

  // Unprotects any RWX intervals in the input interval and invalidates code
  // NOTE: CodeInvalidationMutex must be locked when calling this, and if true is returned, kept locked until the write ends.
  bool BeginUntrackedWriteLocked(uint64_t Address, uint64_t Size);

  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRange(uint64_t Address);

  // MADEIRA: what the periodic [dep-off] summary reports. Plain scalars, read without a lock -
  // this is a progress counter, not a decision input.
  struct DEPStats {
    bool Disabled;     // DEP is off for this process (image without NX_COMPAT, or an explicit opt-out)
    uint64_t Regions;  // regions promoted to executable so far - all of them on an execute attempt
    uint64_t Bytes;    // their total size
    uint64_t Declined; // execute attempts where the page was NOT committed+readable, i.e. a real bad branch
  };
  DEPStats GetDEPStats() const;

private:
  // Registers [Address's committed region] as executable because DEP is off for this process.
  // Called ONLY from QueryExecutableRange, i.e. only when the guest actually tries to execute
  // there - there is no eager sweep; see the comment on the definition.
  // Returns the promoted interval, or a zero-size one when the address is not a committed,
  // readable, non-executable page (i.e. a genuine wild branch, which must still fault).
  // NOTE: Must be called with IntervalsLock held exclusively.
  FEXCore::IntervalList<uint64_t>::Interval PromoteDEPRegionLocked(uint64_t Address);
  // The interval-list half of QueryExecutableRange. NOTE: IntervalsLock must be held.
  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRangeLocked(uint64_t Address);

  void DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC);
  void DisableSMCDetection();
  void InvalidateIntervalInternal(uint64_t Address, uint64_t Size);
  // NOTE: This assumed CodeInvalidationMutex is locked by the caller
  void InvalidateIntervalInternalLocked(uint64_t Address, uint64_t Size);

  // NOTE: If ForWriteLocked is true then this assumes CodeInvalidationMutex is locked by the caller,
  // and any code in the range will be invalidated before protection as RWX, otherwise protects as RX if false.
  bool ProtectRWXIntervalsInternal(uint64_t Address, uint64_t Size, bool ForWriteLocked);

  // Returns the correct protection for trapping (removing write) or untrapping (restoring write) an RWX interval.
  // For DEP-promoted regions (originally non-exec), uses PAGE_READONLY/PAGE_READWRITE instead of PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE.
  // NOTE: Must be called with IntervalsLock held.
  ULONG GetTrapProt(uint64_t Address) const;
  ULONG GetUntrapProt(uint64_t Address) const;

  FEXCore::IntervalList<uint64_t> XIntervals;
  FEXCore::IntervalList<uint64_t> RWXIntervals;
  std::shared_mutex IntervalsLock;
  FEXCore::Context::Context& CTX;
  const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads;
  const uint64_t GuestBase {0};
  bool SMCDetectionDisabled {false};                    // Protected by IntervalsLock
  bool DEPDisabled {false};                             // Protected by IntervalsLock
  FEXCore::IntervalList<uint64_t> DEPPromotedIntervals; // Protected by IntervalsLock
  // Progress counters for the periodic [dep-off] line. Written under IntervalsLock, read without.
  std::atomic<uint64_t> DEPPromotedRegions {0};
  std::atomic<uint64_t> DEPPromotedBytes {0};
  std::atomic<uint64_t> DEPDeclined {0};

  bool MonoBackpatcherDetectionPending {false};
  uint64_t MonoBase {0};
  uint64_t MonoEnd {0};
};
} // namespace FEX::Windows
