// NeacSafe64 client — minifilter R/W bridge for the dumper.
//
// Adapted from D:\GHaxLabs\DayZ\src\Driver\driver.cpp (Frostline / GHax Labs
// DayZ Free), trimmed of cheat-specific bits (VMProtect markers, MessageBox
// UI, driver-fetch dependency) and extended with an embedded-driver fallback
// so the dumper EXE is self-contained.
//
// Protocol summary:
//   Port:         "\OWNeacSafePort"
//   Handshake:    NEAC_FILTER_CONNECT { 0x4655434B, 8, "FuckKeen…(32B)" }
//   Opcodes:      9 (read), 61 (write), 60 (protect), 32 (get-base)
//   Payload:      packet padded to 16-byte boundary, XOR'd with 32B key,
//                 then SSE2 per-16B encrypt() round.
#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>

namespace driver {

// Open `\OWNeacSafePort`. If the driver isn't already loaded, write the
// service key + NtLoadDriver it. The driver image is looked up at:
//   1. %LOCALAPPDATA%\GHax Labs\Driver.sys
//   2. <Updater.exe folder>\Driver.sys
//   3. As a last resort, extracted from the IDR_NEACSAFE_DRIVER RCDATA
//      resource embedded in the EXE to %LOCALAPPDATA%\GHax Labs\Driver.sys
//      and loaded from there.
bool ConnectDriver();
void DisconnectDriver();

bool     AttachToProcess(DWORD pid);
bool     AttachToProcessName(const char* name);
DWORD    GetAttachedPid();
uint64_t GetProcessBase();

bool ReadMem (uint64_t addr, void* buf, size_t len);
bool WriteMem(uint64_t addr, const void* buf, size_t len);

// "NeacSafe64" when connected, "-" otherwise.
const char* DriverLabel();

} // namespace driver
