// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>

namespace FEX::Windows::Logging {
void Init();

// MADEIRA: write one already-formatted string straight to the process's real stderr, WITHOUT
// going through LogMan.
//
// LogMan drops every message until Init() has installed the handlers, so anything a module wants
// to say before that - in particular a fatal reason for refusing to start - vanishes. That is
// exactly what happened on the FIFTH DEVICE RUN: BTCpuProcessInit died on an ERROR_AND_DIE_FMT
// before Logging::Init() and the log showed only the `hlt #1` with no text at all.
//
// Implemented over ntdll's __wine_dbg_output (the same path ntdll's own ERR() lines take, which
// does reach Documents/madeira-log.txt), falling back to WriteFile on hStdError.
void RawWrite(const char* Str, size_t Len);
} // namespace FEX::Windows::Logging
