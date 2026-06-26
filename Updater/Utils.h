#pragma once

namespace Utils {

	bool GetProcessId(const char* Process, PDWORD Pid);
	bool GetFullPath(DWORD ProcessId, const char** Path);
	bool GetProcessBase(const char* Process, PUINT64 ModuleBase, PBYTE* Allocated = NULL);
	bool GetProcessBase(DWORD ProcessId, PUINT64 ModuleBase, PBYTE* Allocated = NULL);
	// Load the binary directly from a file path (used when DayZ isn't
	// running — we LoadLibrary the exe ourselves and pattern-scan its
	// allocated image).
	bool GetBaseFromPath(const char* Path, PUINT64 ModuleBase, PBYTE* Allocated);

	UINT64 PatternScan(UINT64 Module, PBYTE Allocated, const char* Section, PBYTE Pattern, const char* Mask);

	bool DataCompare(PBYTE Data, PBYTE Pattern, const char* Mask);
}