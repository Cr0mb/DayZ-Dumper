#include "Framework.h"

bool Utils::GetProcessId(const char* Process, PDWORD Pid) {

	if (!Pid)	/* are you retarded? */
		return false;

	auto Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (!Snapshot)
		return 0;

	PROCESSENTRY32 Entry;
	Entry.dwSize = sizeof(Entry);

	if (Process32First(Snapshot, &Entry)) {
		do {

			/* Love & affection */
			if (!strcmp(Entry.szExeFile, Process)) 
				*Pid = Entry.th32ProcessID;
			
		} while (Process32Next(Snapshot, &Entry) && !*Pid);
	}

	(void)CloseHandle(Snapshot);

	return *Pid;
}

/* REMEMBER TO FREE THIS AFTER DONE */
bool Utils::GetFullPath(DWORD ProcessId, const char** Path) {

	auto Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);

	if (!Process)
		return false;

	*Path = new char[MAX_PATH];
	DWORD BufferSize = MAX_PATH;

	return (bool)QueryFullProcessImageNameA(Process, NULL, (LPSTR)*Path, &BufferSize);
}

/* this is very haram maybe? */
bool Utils::GetProcessBase(const char* Process, PUINT64 ModuleBase, PBYTE* Allocated) {

	if (!ModuleBase) /* you're braindead! */
		return false;

	DWORD Pid = 0;

	if (!GetProcessId(Process, &Pid))
		return false;

	return GetProcessBase(Pid, ModuleBase, Allocated);
}

/* i hate this, i abseloutely hate it. */
bool Utils::GetProcessBase(DWORD ProcessId, PUINT64 ModuleBase, PBYTE* Allocated) {

	if (!ModuleBase) /* you're braindead! */
		return false;

	const char* Path;

	if (!GetFullPath(ProcessId, &Path))
		return false;

	auto Module = (UINT64)LoadLibraryA(Path);

	if (!Module)
		return false;

	delete Path;

	bool Deallocate = true;

	if (Allocated) {

		*Allocated = (PBYTE)(Module);

		Deallocate = false;
	}

	if (Deallocate)
		FreeLibrary((HMODULE)Module);

	*ModuleBase = Module;

	return true;

}

// Loads the binary at `Path` via LoadLibraryA and returns module base +
// allocated pointer. Used when DayZ isn't running — we still need the
// image loaded into our address space to pattern-scan it.
bool Utils::GetBaseFromPath(const char* Path, PUINT64 ModuleBase, PBYTE* Allocated) {
    if (!Path || !ModuleBase) return false;
    auto Module = (UINT64)LoadLibraryA(Path);
    if (!Module) {
        printf("[UPDATER] LoadLibraryA('%s') failed, err=%lu\n", Path, GetLastError());
        return false;
    }
    *ModuleBase = Module;
    if (Allocated) *Allocated = (PBYTE)Module;
    return true;
}

UINT64 Utils::PatternScan(UINT64 Module, PBYTE Allocated, const char* Section, PBYTE Pattern, const char* Mask) {

	if (!Allocated)	/* retardo */
		return NULL;

	auto Dos = (PIMAGE_DOS_HEADER)(Allocated);

	if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	auto Nt = (PIMAGE_NT_HEADERS)(Allocated + Dos->e_lfanew);

	auto Info = IMAGE_FIRST_SECTION(Nt);

	for (auto i = 0; i < Nt->FileHeader.NumberOfSections; i++, Info++) 
		for (auto j = Info->VirtualAddress; j < Info->SizeOfRawData; j++) 
			if (DataCompare(Allocated + j, Pattern, Mask))
				return Module + j;
	
	return NULL;
}

bool Utils::DataCompare(PBYTE Data, PBYTE Pattern, const char* Mask) {
	/* god bless the champ that made this funcenz */

	for (; *Mask; ++Mask, ++Data, ++Pattern)
		if (*Mask == 'x' && *Data != *Pattern)
			return FALSE;

	return (*Mask == NULL);
}