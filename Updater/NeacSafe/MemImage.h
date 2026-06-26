// Reconstruct a live process's mapped PE image into a flat heap buffer
// using NeacSafe64's minifilter R/W primitive. The buffer is laid out so
// that PointerToRawData == VirtualAddress for every section — matches what
// LoadLibraryA produces, so the dumper's PatternScan walks it unchanged.
//
// Required for the Microsoft Store / Game Pass build, whose on-disk PE is
// clipsp-encrypted and rejects LoadLibraryA. The decrypted PE only exists
// in the running process's memory; NeacSafe64 reads it via its FltMgr
// channel, bypassing BattlEye's ObRegisterCallbacks handle stripping.
#pragma once
#include <Windows.h>
#include <cstdint>

namespace MemImage {

// On success: *outModule = (UINT64)buffer, *outAllocated = buffer.
// Caller does not free — process exit reclaims (matches the LoadLibraryA
// path which also leaks). Returns false on any of: process not running,
// NeacSafe64 not loadable, image base = 0, header read failure, or
// implausible SizeOfImage.
bool DumpLive(const char* processName, UINT64* outModule, PBYTE* outAllocated);

// Write the most-recently-reconstructed image to disk for static analysis.
// Call after a successful DumpLive(). Returns false if no image is held or
// the write fails.
bool SaveLastTo(const char* path);

} // namespace MemImage
