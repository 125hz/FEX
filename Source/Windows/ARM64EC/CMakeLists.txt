add_library(arm64ecfex SHARED
  Module.cpp
  Module.S
  IosJitAlias.cpp
  libarm64ecfex.def
  $<TARGET_OBJECTS:FEXCore_object>)

patch_library_wine(arm64ecfex)

target_include_directories(arm64ecfex PRIVATE
  "${CMAKE_SOURCE_DIR}/Source/Windows/include/"
  "${CMAKE_SOURCE_DIR}/Source/"
  "${CMAKE_SOURCE_DIR}/Source/Windows/")

# MADEIRA 2026-09-23: FEX_IOS_HOST MUST REACH Module.S, NOT JUST THE C/C++ TUs.
#
# The iOS build passed the define through -DCMAKE_C_FLAGS / -DCMAKE_CXX_FLAGS only.
# `project(FEX C CXX ASM)` compiles a .S file with the ASM language, whose flags come
# from CMAKE_ASM_FLAGS — which never carried it. Every `#ifdef FEX_IOS_HOST` block in
# Module.S was therefore assembled AWAY, silently, in a DLL whose C++ half was built
# WITH the define: no warning, no link error, a working-looking binary.
#
# What that cost: ExitFunctionEC shipped without the JIT-pool alias translation, so
# every x86-64 -> ARM64EC call branched to the target's ORIGINAL (non-executable) PE
# VA and paid a full Mach exception round trip. A device run of a 64-bit title sat at
# 100% CPU with 446,464 such redirects through three ucrtbase entry points; the
# `wine-x18-exc` thread alone held 25% of all CPU. `ExitToX64`'s fast-forward-sequence
# bypass and `enter_jit`'s code-buffer sweep gate were missing for the same reason.
# Verified by disassembling the shipped DLL: `ldr x16, [x18, #0x60]` — the #else arm.
#
# target_compile_definitions feeds <DEFINES> to the ASM rule as well as C/C++, so the
# one true source of the flag lives here, with the target, and cannot be lost by a
# build script that forgets a variable. Module.S additionally defines a symbol the C++
# side references, so a mismatched build now fails to LINK instead of shipping.
if (FEX_IOS_HOST_BUILD)
  target_compile_definitions(arm64ecfex PRIVATE FEX_IOS_HOST)
endif()

target_link_libraries(arm64ecfex PRIVATE
  FEXCore_Base
  Common
  CommonTools
  CommonWindows
  CommonWindowsRuntime
  ntdll_ex)

# Upstream FEX uses `-static -nostdlib -nostartfiles -nodefaultlibs` to avoid
# pulling in mingw's CRT, then re-adds libc++/libc++abi/libunwind manually.
# This works on Linux-host arm64ec builds but FAILS on macOS-host llvm-mingw
# 22.1.4: ld.lld can't reconcile EC-mangled defs in libc++abi.a against
# non-EC-mangled refs from C++ frontend code, and segfaults on the link.
#
# For our iOS-host build, fall through to the default mingw link rules —
# they include the right startup files, CRT, and produce a clean arm64ec PE.
# The resulting DLL is slightly larger but links cleanly.
if (FEX_IOS_HOST_BUILD)
  target_link_options(arm64ecfex PRIVATE -static)
else()
  target_link_options(arm64ecfex PRIVATE -static -nostdlib -nostartfiles -nodefaultlibs -lc++ -lc++abi -lunwind)
  target_link_libraries(arm64ecfex PRIVATE ${LIBGCC_PATH})
endif()
install(TARGETS arm64ecfex RUNTIME
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  COMPONENT Runtime)
