// SPDX-License-Identifier: MIT
#pragma once
/*
 * iOS-Madeira ml930 — PUBLISHED HOST-PC → GUEST-RIP MAP FOR THE [prof] SAMPLER.
 *
 * WHY THIS EXISTS. The ntdll-unix sampling profiler ([prof], signal_arm64_ios.c)
 * gets one thing per sample: a host PC. When that PC lands in the JIT pool tail
 * it is FEX-generated code, and until now the only way back to a guest RIP was
 * ios_fex_rip_from_hostpc(BlockBegin, HostPC) — which needs the BLOCK BEGIN, and
 * the only source of that is State.InlineJITBlockHeader (x28+0) of the sampled
 * thread. That value is the block the thread ENTERED, not necessarily the code it
 * is executing: every sample taken in the dispatcher, in a dispatcher helper, in
 * an interpreter fallback thunk, or after a stale thread_get_state() reports
 * "hostPC outside block" and is lost. In the device log that was NEARLY EVERY JIT
 * SAMPLE, i.e. 22–53 % of all CPU was attributed to "the JIT" with no idea which
 * guest module it belonged to.
 *
 * So publish the mapping instead of trying to reconstruct it. Every compile
 * appends (HostStart, HostSize, GuestRIP, per-block op counts) to a ring, and the
 * ring's address is published through a single DATA export of the WoW64 module
 * (BTCpuIosProfMap). The sampler reads it with mach_vm_read_overwrite only — it
 * never calls into this module, which is the ml613/ml614 trap that crashed every
 * launch when an ARM64EC PE export was called from native code.
 *
 * CONTRACT / INVARIANTS
 *  - Append-only ring, claimed with one relaxed fetch_add. No locks: the sampler
 *    tolerates a torn entry (it can only misattribute one sample), and the
 *    compile path must never block on a diagnostic.
 *  - The reader NEVER assumes the ring is sorted. It streams every slot and tests
 *    containment, preferring the youngest match (recency = distance from Head),
 *    so a host range recycled by ClearCodeCache resolves to its newest owner.
 *  - GuestRIP is stored as uint32_t: in the 32-bit WoW64 module RIPs are guest
 *    namespace (< 4 GB) by WOW64_DESIGN.md §2/§3 invariant 1. Enabled only there.
 *  - Nothing is allocated until the sampler sets Enable, so a run without [prof]
 *    pays a single predictable load per COMPILE (not per execution) and 0 bytes.
 *  - Entry counts are saturating uint16 and are per-BLOCK, which is what lets the
 *    sampler weight "x87 present" by samples instead of by compile count.
 */

#ifdef FEX_IOS_HOST

#include <atomic>
#include <cstdint>

namespace FEXCore::IR {
enum IROps : uint16_t;
}

namespace FEXCore::IosProfMap {

#define FEX_IOSPROFMAP_MAGIC   0x314d5049u /* "IPM1" */
#define FEX_IOSPROFMAP_VERSION 1u

// 24 bytes. Mirrored byte-for-byte by struct ios_profblk in
// build/ntdll-unix/signal_arm64_ios.c — change both or neither.
struct Block {
  uint64_t HostStart;
  uint32_t HostSize;
  uint32_t GuestRIP;
  uint16_t NumInst;
  uint16_t NumX87;
  uint16_t NumVec;
  uint16_t NumTSO;
};
static_assert(sizeof(Block) == 24, "ABI shared with signal_arm64_ios.c");

// One named region of the dispatcher's 16 KB buffer. The device log showed
// 10–27 % of all CPU inside the dispatcher with no way to say WHICH helper, so
// the map is published rather than inferred from emission order.
struct DispRegion {
  uint64_t Begin;
  char Name[24];
};
static constexpr uint32_t MaxDispRegions = 64;

struct Header {
  uint32_t Magic;
  uint32_t Version;
  uint32_t EntrySize;
  uint32_t Capacity; // power of two
  std::atomic<uint32_t> Enable;
  uint32_t Bitness;
  std::atomic<uint64_t> Head; // total appends ever; slot = index & (Capacity-1)
  uint64_t Entries;           // host address of the ring; 0 until Enable is seen
  uint64_t GuestBase;         // B, WOW64_DESIGN.md §2
  uint64_t DispatcherBegin;
  uint64_t DispatcherEnd;
  uint32_t NumDispRegions;
  uint32_t _pad0;
  // Process-wide emission-time accumulators (never reset by this side; the
  // sampler differences them across its report windows).
  std::atomic<uint64_t> X87Ops;
  std::atomic<uint64_t> VecOps;
  std::atomic<uint64_t> AtomicOps;
  std::atomic<uint64_t> TSOOps;
  std::atomic<uint64_t> GuestInsts;
  std::atomic<uint64_t> HostBytes;
  std::atomic<uint64_t> Blocks;
  std::atomic<uint64_t> AllocFailed;
  DispRegion DispRegions[MaxDispRegions];
};

extern Header Hdr;

// True once the sampler has asked for the map AND the ring exists. The compile
// path calls this; it is one relaxed load.
bool Enabled();

// Append one compiled block. Safe to call from any compiling thread.
void Record(uint64_t HostStart, uint64_t HostSize, uint64_t GuestRIP, uint32_t NumInst, uint32_t NumX87, uint32_t NumVec, uint32_t NumAtomic,
            uint32_t NumTSO);

// Called from Dispatcher::EmitDispatcher as each named region is emitted.
// Several pseudo-processes share this Mach task and each builds its own
// dispatcher, so the table always describes the MOST RECENT one — exactly like
// the [disp-addrs] line it extends. Clear first, then add, then set the range;
// the sampler bounds every lookup by DispatcherBegin/End, so a PC belonging to
// an older dispatcher simply does not match instead of being misnamed.
void ClearDispRegions();
void AddDispRegion(const char* Name, uint64_t Begin);
void SetDispatcherRange(uint64_t Begin, uint64_t End);

// 0 none / 1 x87 / 2 vector / 3 atomic / 4 TSO memory op. Built once from
// FEXCore::IR::GetName so no hand-maintained opcode list can drift.
uint8_t ClassifyOp(FEXCore::IR::IROps Op);

} // namespace FEXCore::IosProfMap

#endif
