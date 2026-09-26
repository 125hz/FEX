// SPDX-License-Identifier: MIT
/*
$info$
category: backend ~ IR to host code generation
tags: backend|shared
$end_info$
*/

#pragma once

#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/map.h>

#include <cstdint>
#ifdef FEX_IOS_HOST
#include <atomic>
#include <mutex>
#endif

namespace FEXCore::CPU {
union Relocation;
}

namespace FEXCore {

namespace IR {
  class IRListView;
} // namespace IR

namespace Core {
  struct DebugData;
  struct ThreadState;
  struct CpuStateFrame;
  struct InternalThreadState;
} // namespace Core

namespace CodeSerialize {
  struct CodeObjectFileSection;
}

struct GuestToHostMap;

namespace CPU {
#ifdef FEX_IOS_HOST
  // ml460 (#75): monotonically increasing CodeBuffer generation number,
  // bumped on every AllocateNew. Drives the deferred pool-tail sweep.
  uint64_t IosCodeBufferGeneration();
#endif

  struct CodeBuffer {
    uint8_t* Ptr;
    size_t AllocatedSize; // including guard page; see UsableSize()

    fextl::unique_ptr<GuestToHostMap> LookupCache;

    CodeBuffer(size_t Size);
    CodeBuffer(const CodeBuffer&) = delete;
    CodeBuffer& operator=(const CodeBuffer&) = delete;
    CodeBuffer(CodeBuffer&& oth) = delete;
    CodeBuffer& operator=(CodeBuffer&&) = delete;

    ~CodeBuffer();

    /// Returns the number of bytes available for storing code
    size_t UsableSize() const {
      return AllocatedSize - FEXCore::Utils::FEX_PAGE_SIZE;
    }
  };

  /**
   * A manager that coordinates access to the CodeBuffer used for compiling new code across threads.
   *
   * The CodeBuffer is managed as a partially persistent data structure:
   * - Exactly one CodeBuffer is now designated as "active", which means data can be appended to it
   * - Lossy modifications to the active CodeBuffer will not invalidate any data in use by other threads (which is what enables save CodeBuffer sharing across threads)
   * - Instead, such lossy modifications trigger a new "version" of the data in the modifying thread. Old versions of the CodeBuffer persist as read-only data for use by the other threads.
   * - The other threads can update their version of the CodeBuffer. This will decrease the reference count and eventually trigger deallocation of the old version
   */
  class CodeBufferManager {
  public:
    // Get the CodeBuffer that was most recently allocated.
    // This is the only CodeBuffer that data may be written to.
    fextl::shared_ptr<CodeBuffer> GetLatest();

    // Allocate a new CodeBuffer with geometric growth up to an internal maximum.
    // Subsequent calls to GetLatest will point to the returned buffer.
    fextl::shared_ptr<CodeBuffer> StartLargerCodeBuffer();

    // Write offset into the latest CodeBuffer
    std::size_t LatestOffset {};

    // Protects writes to the latest CodeBuffer and changes to LatestOffset
    FEXCore::ForkableUniqueMutex CodeBufferWriteMutex;

    virtual void OnCodeBufferAllocated(const std::shared_ptr<CodeBuffer>&) {};

#ifdef FEX_IOS_HOST
    /* iOS-Madeira ml460 (#75): the pool-tail sweeper (Module.cpp) reads Latest
     * WITHOUT holding CodeBufferWriteMutex, racing AllocateNew's assignment.
     * A shared_ptr copy concurrent with an assignment is UB, so both go
     * through this small leaf mutex. Never held while acquiring any other
     * lock (assignment + copy only). */
    std::mutex LatestMutex;
#endif

  private:
    fextl::shared_ptr<CodeBuffer> Latest;

#ifdef FEX_IOS_HOST
    /* ml1020 (#86): the size we last ASKED for, which is NOT the size we got.
     *
     * On iOS every code buffer is carved from the finite JIT pool, and a refused
     * carve is degraded rather than failed: CodeBuffer's ctor halves the request
     * down (rev=ml364, "[code-buffer] exec alloc degraded"). StartLargerCodeBuffer
     * used to compute the next size from Latest->AllocatedSize — the DEGRADED
     * value — so one transient refusal ratcheted the whole process down a size
     * ladder it could never climb back up. w50 shows it exactly: allocations #2
     * through #15 are 32MB, then #16 is 16MB, #17 8MB, #28 4MB, #31 2MB, and from
     * there the run alternates 1MB/2MB for 20+ more generations while 240MB of
     * 16-32MB carves sit pinned. Small buffers rotate ~32x more often, each
     * rotation is a ClearCodeCache that wipes every thread's L1/L2 (w50's
     * real_compile spike of +72960 blocks in one 10s window), and the rotation
     * storm is what eventually caught a moment with zero free carves.
     *
     * The ladder is kept here instead, monotonic up to MAX_CODE_SIZE, so a
     * degraded grant costs ONE generation rather than the rest of the session.
     * MADEIRA_FEX_RECYCLE=0 restores the pre-ml1020 "double the granted size". */
    size_t DesiredSize {};
#endif

    fextl::shared_ptr<CodeBuffer> AllocateNew(size_t Size);
  };

  class CPUBackend {
  public:

    CPUBackend(CodeBufferManager&, FEXCore::Core::InternalThreadState*);

    virtual ~CPUBackend();

    struct CompiledCode {
      // Where this code block begins.
      uint8_t* BlockBegin;
      fextl::map<uint64_t, uint8_t*> EntryPoints;
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;
    };

    // Header that can live at the start of a JIT block.
    // We want the header to be quite small, with most data living in the tail object.
    struct JITCodeHeader {
      // Offset from the start of this header to where the tail lives.
      // Only 32-bit since the tail block won't ever be more than 4GB away.
      uint32_t OffsetToBlockTail;
    };

    // Header that can live at the end of the JIT block.
    // For any state reconstruction or other data, this is where it should live.
    // Any data that is explicitly tied to the JIT code and needs to be cached with it
    // should end up in this data structure.
    struct JITCodeTail {
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;

      // RIP that the block's entry comes from.
      uint64_t RIP;

      // The length of the guest code for this block.
      size_t GuestSize;

      // Number of RIP entries for this JIT Code section.
      uint32_t NumberOfRIPEntries;

      // Offset after this block to the start of the RIP entries.
      uint32_t OffsetToRIPEntries;

      // Shared-code modification spin-loop futex.
      uint32_t SpinLockFutex;

      // If this block represents a single guest instruction.
      bool SingleInst;

      uint8_t _Pad[3];
    };

    /**
     * @brief Tells this CPUBackend to compile code for the provided IR and DebugData
     *
     * The returned pointer needs to be long lived and be executable in the host environment
     * FEXCore's frontend will store this pointer in to a cache for the current RIP when this was executed
     *
     * This is a thread specific compilation unit since there is one CPUBackend per guest thread
     *
     * @param Size - The byte size of the guest code for this block
     * @param SingleInst - If this block represents a single guest instruction
     * @param IR -  IR that maps to the IR for this RIP
     * @param DebugData - Debug data that is available for this IR indirectly
     * @param CheckTF - If EFLAGS.TF checks should be emitted at the start of the block
     *
     * @return Information about the compiled code block.
     */
    [[nodiscard]]
    virtual CompiledCode CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst, const FEXCore::IR::IRListView* IR,
                                     FEXCore::Core::DebugData* DebugData, bool CheckTF) = 0;

    virtual fextl::vector<FEXCore::CPU::Relocation> TakeRelocations(uint64_t GuestBaseAddress) = 0;

    virtual void ClearCache() {}

    /**
     * @brief Clear any relocations after JIT compiling
     */
    virtual void ClearRelocations() {}

    bool IsAddressInCodeBuffer(uintptr_t Address) const;

    // Updates the CodeBuffer if needed and returns a reference to the old one.
    // The returned reference should be kept alive carefully to avoid early deletion of resources.
    [[nodiscard]]
    fextl::shared_ptr<CodeBuffer> CheckCodeBufferUpdate();

#ifdef FEX_IOS_HOST
    /* iOS-Madeira ml460 (#75 pool exhaustion): CurrentCodeBuffer pins a whole
     * generation for as long as this thread holds the ref, and the ONLY
     * release sites are compile-path self-migrations — so a thread parked in
     * a wine wait pins its generation for the entire park (ml459 census: 13
     * 16MB generations live, 0 free, 208MB of a 896MB pool, while steady
     * state needs ~2). The sweeper (Module.cpp IosMaybeSweepCodeBuffers)
     * remote-migrates parked threads. Concurrency: the asm-side Dekker gate
     * (IosCodeBufferSweepGate vs InSimulation) keeps the OWNER out of
     * emitted-code use of L1/callret during a sweep; this per-thread spin
     * lock serializes every C++ toucher of CurrentCodeBuffer /
     * SignalHandlerCodeBuffers (self compile paths, exception-path queries,
     * the sweeper). Lock order where nested: LookupCache write lock, THEN
     * IosMigrateLock. LatestMutex is never held around either. */
    mutable std::atomic<uint32_t> IosMigrateLock {0};
    /* ml630 (#78 5-10 minute freeze): the lock above is a plain test-and-set
     * spin with no owner and no bound, and IsAddressInCodeBuffer - the
     * "is this host pc JIT code?" query that EVERY fault runs - used to take
     * it. Any host fault taken inside a critical section (a pool commit
     * fault, an RWX/SMC write fault, the JIT guard page, a Mach-side
     * redirect) re-enters the query on the SAME thread and spins on a lock
     * that thread already holds, forever; the sweeper then piles up behind it
     * still holding a LookupCache write lock and the whole process parks.
     *
     * The query now reads this lock-free table instead and never blocks.
     * Each live code buffer occupies ONE 64-bit slot encoding
     *   (Base >> FEX_PAGE_SHIFT) << IosRangePageBits | UsablePageCount
     * so a slot is a single atomic word: a reader observes either the old
     * value or the new one, never a mixed {base,size} pair, and no sequence
     * counter or retry loop is needed. 0 means "empty slot".
     *
     * Writers are the three mutators of CurrentCodeBuffer /
     * SignalHandlerCodeBuffers and are still serialized by IosMigrateLock, so
     * there is exactly one publisher at a time. Bases come from the iOS JIT
     * pool (< 2^56) and buffers are capped at MAX_CODE_SIZE (32MB = 8192
     * pages), so both fields always fit; IosRangesDegraded latches if that
     * ever stops being true or more than IosMaxPublishedRanges buffers are
     * live, and only then does the query fall back to the locked path. */
    static constexpr size_t IosMaxPublishedRanges = 32;
    static constexpr uint32_t IosRangePageBits = 20;
    mutable std::atomic<uint64_t> IosPublishedRanges[IosMaxPublishedRanges] {};
    mutable std::atomic<uint32_t> IosRangesDegraded {0};
    // Owner TEB of the current IosMigrateLock holder, 0 when free. Makes the
    // lock recursion-tolerant so that no path reachable from a fault taken
    // inside a critical section can self-deadlock on it.
    mutable std::atomic<uint64_t> IosMigrateOwner {0};
    mutable uint32_t IosMigrateDepth {0};
    // Republishes IosPublishedRanges from CurrentCodeBuffer +
    // SignalHandlerCodeBuffers. Caller must hold IosMigrateLock.
    void IosPublishCodeBufferRanges();
    // Same, but takes IosMigrateLock itself. For the one assignment that
    // happens outside any critical section (the Arm64JITCore constructor).
    void IosPublishCodeBufferRangesLocked();
    // Returns 1 = migrated, 0 = nothing to do, -1 = skipped (signal frames
    // in flight), -2 = raced out. Caller must have established via the sweep
    // gate that this thread is outside emitted code (InSimulation == 0).
    int IosRemoteMigrateStale(const fextl::shared_ptr<CodeBuffer>& LatestBuf);
    CodeBufferManager& GetCodeBufferManager() {
      return CodeBuffers;
    }
#endif

  protected:
    // Max spill slot size in bytes. We need at most 32 bytes
    // to be able to handle a 256-bit vector store to a slot.
    constexpr static uint32_t MaxSpillSlotSize = 32;

    FEXCore::Core::InternalThreadState* ThreadState;

    [[nodiscard]]
    CodeBuffer* GetEmptyCodeBuffer();

    // This is the code buffer containing the main code under execution by this thread.
    // CheckCodeBufferUpdate must be used before compiling new code.
    fextl::shared_ptr<CodeBuffer> CurrentCodeBuffer;

    // Old CodeBuffer generations required to be valid until returning from signal handlers
    fextl::vector<fextl::shared_ptr<CodeBuffer>> SignalHandlerCodeBuffers;

    CodeBufferManager& CodeBuffers;

  private:
    void RegisterForSignalHandler(fextl::shared_ptr<CodeBuffer>);
  };

} // namespace CPU
} // namespace FEXCore
