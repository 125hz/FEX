// SPDX-License-Identifier: MIT

#include "Common/CPUInfo.h"

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/fextl/fmt.h>

#include <windows.h>

#include <cstdlib>
#include <cstring>

#include "CPUFeatures.h"

namespace {

HKEY OpenProcessorKey(uint32_t Idx) {
  HKEY Out;
  auto Path = fextl::fmt::format("Hardware\\Description\\System\\CentralProcessor\\{}", Idx);
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, Path.c_str(), 0, KEY_READ, &Out)) {
    return nullptr;
  }
  return Out;
}

uint64_t ReadRegU64(HKEY Key, const char* Name) {
  uint64_t Value = 0;
  DWORD Size = sizeof(Value);
  RegGetValueA(Key, nullptr, Name, 0, nullptr, &Value, &Size);
  return Value;
}

} // namespace

namespace FEX::Windows {
#define GetSysReg(name, reg)                         \
  static uint64_t Get_##name() {                     \
    uint64_t Result {};                              \
    __asm("mrs %[Res], " #reg : [Res] "=r"(Result)); \
    return Result;                                   \
  }
GetSysReg(DCZID_EL0, DCZID_EL0);

class CPUFeaturesFromRegistry final : public FEX::CPUFeatures {
public:
  explicit CPUFeaturesFromRegistry(HKEY Key) {
    ISAR0.SetReg(ReadRegU64(Key, "CP 4030"));
    PFR0.SetReg(ReadRegU64(Key, "CP 4020"));
    PFR1.SetReg(ReadRegU64(Key, "CP 4021"));
    ISAR1.SetReg(ReadRegU64(Key, "CP 4031"));
    MMFR0.SetReg(ReadRegU64(Key, "CP 4038"));
    MMFR2.SetReg(ReadRegU64(Key, "CP 403A"));
    ZFR0.SetReg(ReadRegU64(Key, "CP 4024"));
    MMFR1.SetReg(ReadRegU64(Key, "CP 4039"));
    ISAR2.SetReg(ReadRegU64(Key, "CP 4032"));
    DCZID.SetReg(Get_DCZID_EL0());
    FillFeatureFlags();
  }
};

FEXCore::HostFeatures CPUFeatures::FetchHostFeatures(bool IsWine, FEXCore::HostFeatures::HostTypeEnum HostType) {
#ifdef FEX_IOS_HOST
  /* iOS-Madeira: registry has nothing useful here (Hardware\... reg keys
   * aren't populated). Synthesize a minimal HostFeatures manually with
   * baseline ARMv8.2 features that Apple Silicon supports. */
  FEXCore::HostFeatures HostFeatures = {};
  HostFeatures.DCacheLineSize = 64;
  HostFeatures.ICacheLineSize = 64;
  HostFeatures.SupportsCacheMaintenanceOps = !IsWine;
  HostFeatures.SupportsAES = true;
  HostFeatures.SupportsCRC = true;
  HostFeatures.SupportsAtomics = true;
  HostFeatures.SupportsRCPC = true;
  HostFeatures.SupportsSHA = true;
  HostFeatures.SupportsPMULL_128Bit = true;
  HostFeatures.SupportsFCMA = true;
  HostFeatures.SupportsFlagM = true;
  HostFeatures.SupportsFlagM2 = true;
  HostFeatures.SupportsAFP = true;

  /* MADEIRA ml970: FEAT_LRCPC2 (SupportsTSOImm9) is OPT-IN here, and off by
   * default, because this branch cannot probe for it.
   *
   * What it buys, measured on the [prof] hot-block dumps of a 32-bit D3D9
   * title: with SupportsTSOImm9 false every TSO access is emitted as
   * `<addr arithmetic>; add x24, x19, wN, uxtw; ldapr/stlr wR, [x24]',
   * because LDAPR/STLR have no offset form at all and IREmitter.h's
   * `IsSIMM9 &= (SupportsTSOImm9 || !TSO)' therefore refuses to fold ANY
   * displacement into a TSO op.  One guest `add [ebp-516], reg' costs nine
   * host instructions, four of which are address arithmetic that
   * `ldapur/stlur wR, [x24, #-516]' would absorb outright.  The unaligned
   * back-patcher already decodes and rewrites both forms
   * (FEXCore/Source/Utils/ArchHelpers/Arm64.cpp: LDAPUR_INST/STLUR_INST at
   * :2202, :2352, :2412), so nothing downstream needs to change.
   *
   * WHY IT IS NOT ON BY DEFAULT.  FEAT_LRCPC2 is ARMv8.4; the app's iOS 18
   * floor admits A12/A13, which are ARMv8.3 and implement LRCPC but NOT
   * LRCPC2, so an unconditional `true' here would emit an undefined
   * instruction in every JIT block on those devices.  Detecting it properly
   * needs `hw.optional.arm.FEAT_LRCPC2' from sysctl, which is a unix-side
   * call this PE module cannot make (FEXUnixLib's func table is not
   * registered on the iOS host -- see TryEnableHardwareTSO), so until that
   * table exists the honest form of this knob is a user opt-in that the
   * device owner sets after checking their own silicon.
   *
   * Spelling matches upstream's own FEX_HOSTFEATURES token so nothing new
   * has to be learned: `HOSTFEATURES=ENABLELRCPC2' in
   * Documents/madeira-fex.txt.  FEX::FetchHostFeatures/OverrideFeatures --
   * which is what parses that variable on a Linux host -- is never reached
   * on this branch, which is why it is read directly here. */
  if (const char* HostFeaturesEnv = getenv("FEX_HOSTFEATURES");
      HostFeaturesEnv && strstr(HostFeaturesEnv, "ENABLELRCPC2")) {
    HostFeatures.SupportsTSOImm9 = true;
  }

  HostFeatures.CPUMIDRs.push_back(0u);
  HostFeatures.HostType = HostType;
  return HostFeatures;
#else
  HKEY Key = OpenProcessorKey(0);
  if (!Key) {
    ERROR_AND_DIE_FMT("Couldn't detect CPU features");
  }

  CPUFeaturesFromRegistry Features(Key);

  uint64_t CTR = ReadRegU64(Key, "CP 5801");
  uint64_t MIDR = ReadRegU64(Key, "CP 4000");

  FEXCore::HostFeatures HostFeatures = {};

  for (uint32_t Idx = 0; Key; Key = OpenProcessorKey(++Idx)) {
    // Truncate to 32-bits, top 32-bits are all reserved in MIDR
    HostFeatures.CPUMIDRs.push_back(static_cast<uint32_t>(ReadRegU64(Key, "CP 4000")));
    RegCloseKey(Key);
  }

  FEX::FetchHostFeatures(Features, HostFeatures, !IsWine, CTR, MIDR);

  // Force-disable SVE until wine/windows gain support for SVE context save/restore
  HostFeatures.SupportsSVE128 = false;
  HostFeatures.SupportsSVE256 = false;

  HostFeatures.SupportsCPUIndexInTPIDRRO = !IsWine;

  HostFeatures.HostType = HostType;

  if (HostType == FEXCore::HostFeatures::HostTypeEnum::Wow64) {
    // AVX is unsupported for WOW64
    HostFeatures.SupportsAVX = false;
  }
  return HostFeatures;
#endif
}

CPUFeatures::CPUFeatures(FEXCore::Context::Context& CTX) {
#ifdef ARCHITECTURE_arm64ec
  // Report as a 64-bit host for ARM64EC.
  CpuInfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
#else
  // Report as a 32-bit host for WoW64.
  CpuInfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif

  // Baseline FEX feature-set
  CpuInfo.ProcessorFeatureBits = CPU_FEATURE_VME | CPU_FEATURE_TSC | CPU_FEATURE_CMOV | CPU_FEATURE_PGE | CPU_FEATURE_PSE | CPU_FEATURE_MTRR |
                                 CPU_FEATURE_CX8 | CPU_FEATURE_MMX | CPU_FEATURE_X86 | CPU_FEATURE_PAT | CPU_FEATURE_FXSR | CPU_FEATURE_SEP |
                                 CPU_FEATURE_SSE | CPU_FEATURE_3DNOW | CPU_FEATURE_SSE2 | CPU_FEATURE_SSE3 | CPU_FEATURE_CX128 |
                                 CPU_FEATURE_NX | CPU_FEATURE_SSSE3 | CPU_FEATURE_SSE41 | CPU_FEATURE_PAE | CPU_FEATURE_DAZ;

  // Features that require specific host CPU support
  const auto CPUIDResult01 = CTX.RunCPUIDFunction(0x01, 0);
  if (CPUIDResult01.ecx & (1 << 20)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_SSE42;
  }
  if (CPUIDResult01.ecx & (1 << 27)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_XSAVE;
  }
  if (CPUIDResult01.ecx & (1 << 28)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_AVX;
  }

  const auto CPUIDResult07 = CTX.RunCPUIDFunction(0x07, 0);
  if (CPUIDResult07.ebx & (1 << 5)) {
    CpuInfo.ProcessorFeatureBits |= CPU_FEATURE_AVX2;
  }

  const auto FamilyIdentifier = CPUIDResult01.eax;
  CpuInfo.ProcessorLevel = ((FamilyIdentifier >> 8) & 0xf) + ((FamilyIdentifier >> 20) & 0xff); // Family
  CpuInfo.ProcessorRevision = (FamilyIdentifier & 0xf0000) >> 4;                                // Extended Model
  CpuInfo.ProcessorRevision |= (FamilyIdentifier & 0xf0) << 4;                                  // Model
  CpuInfo.ProcessorRevision |= FamilyIdentifier & 0xf;                                          // Stepping
}

bool CPUFeatures::IsFeaturePresent(uint32_t Feature) {
  switch (Feature) {
  case PF_FLOATING_POINT_PRECISION_ERRATA: return FALSE;
  case PF_FLOATING_POINT_EMULATED: return FALSE;
  case PF_COMPARE_EXCHANGE_DOUBLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_CX8);
  case PF_MMX_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_MMX);
  case PF_XMMI_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE);
  case PF_3DNOW_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_3DNOW);
  case PF_RDTSC_INSTRUCTION_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_TSC);
  case PF_PAE_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_PAE);
  case PF_XMMI64_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE2);
  case PF_SSE3_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE3);
  case PF_SSSE3_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSSE3);
  case PF_XSAVE_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_XSAVE);
  case PF_COMPARE_EXCHANGE128: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_CX128);
  case PF_SSE_DAZ_MODE_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_DAZ);
  case PF_NX_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_NX);
  case PF_SECOND_LEVEL_ADDRESS_TRANSLATION: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_2NDLEV);
  case PF_VIRT_FIRMWARE_ENABLED: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_VIRT);
  case PF_RDWRFSGSBASE_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_RDFS);
  case PF_FASTFAIL_AVAILABLE: return TRUE;
  case PF_SSE4_1_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE41);
  case PF_SSE4_2_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE42);
  case PF_AVX_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_AVX);
  case PF_AVX2_INSTRUCTIONS_AVAILABLE: return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_AVX2);
  default: return false;
  }
}

void CPUFeatures::UpdateInformation(SYSTEM_CPU_INFORMATION* Info) {
  Info->ProcessorArchitecture = CpuInfo.ProcessorArchitecture;
  Info->ProcessorLevel = CpuInfo.ProcessorLevel;
  Info->ProcessorRevision = CpuInfo.ProcessorRevision;
  Info->ProcessorFeatureBits = CpuInfo.ProcessorFeatureBits;
}
} // namespace FEX::Windows
