#include "Framework.h"
#include "NeacSafe/MemImage.h"
#include "NeacSafe/Driver.h"
#include <algorithm>
#include <vector>
#include <cstdarg>
#include <ctime>

// ── Tee logger (console + dump.log next to Updater.exe) ─────────────────
namespace teelog {
    static FILE* g_File = nullptr;

    void Open() {
        char buf[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        char* slash = strrchr(buf, '\\');
        if (slash) { strcpy_s(slash + 1, MAX_PATH - (slash + 1 - buf), "dump.log"); }
        else       { strcpy_s(buf, MAX_PATH, "dump.log"); }
        fopen_s(&g_File, buf, "w");
        if (g_File) {
            time_t t = time(nullptr); struct tm tm; localtime_s(&tm, &t);
            fprintf(g_File,
                "# DayZ-Dumper_v15 dump.log — %04d-%02d-%02d %02d:%02d:%02d\n"
                "# log file: %s\n# tee'd from stdout in real time\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, buf);
            fflush(g_File);
            printf("[UPDATER] log: %s\n", buf);
        } else {
            printf("[UPDATER] WARNING: could not open dump.log for write.\n");
        }
    }
    void Close() {
        if (g_File) { fflush(g_File); fclose(g_File); g_File = nullptr; }
    }
    void Printf(const char* fmt, ...) {
        char line[2048];
        va_list ap;
        va_start(ap, fmt);
        int n = _vsnprintf_s(line, sizeof(line), _TRUNCATE, fmt, ap);
        va_end(ap);
        if (n < 0) return;
        fputs(line, stdout);
        fflush(stdout);
        if (g_File) { fputs(line, g_File); fflush(g_File); }
    }
} // namespace teelog

INT64 AutoOffset::ResolveMovCs(UINT64 Module, UINT64 Instruction) {

	int Relative = *(int*)(Instruction + 3);

	Instruction += 7;

	return (Instruction + Relative) - Module;
}

INT64 AutoOffset::ResolveCmpCs(UINT64 Module, UINT64 Instruction) {

	int Relative = *(int*)(Instruction + 2);

	Instruction += 7;

	return (Instruction + Relative) - Module;
}

INT64 AutoOffset::ResovleMovRegXmm(UINT64 Module, UINT64 Instruction) {
	return *(int*)(Instruction + 4);
}

INT64 AutoOffset::ResolveMovRegXmmLrg(UINT64 Module, UINT64 Instruction) {
	return *(int*)(Instruction + 5);
}

INT64 AutoOffset::ResovleMovRegXmmByte(UINT64 Module, UINT64 Instruction) {
	return *(BYTE*)(Instruction + 4);
}

INT64 AutoOffset::ResovleMovRegXmmLrgByte(UINT64 Module, UINT64 Instruction) {
	return *(BYTE*)(Instruction + 5);
}

INT64 AutoOffset::ResolveMovReg(UINT64 Module, UINT64 Instruction) {
	return *(int*)(Instruction + 3);
}

INT64 AutoOffset::ResolveMovRegByte(UINT64 Module, UINT64 Instruction) {
	return *(BYTE*)(Instruction + 3);
}

INT64 AutoOffset::ResolveMovRegSml(UINT64 Module, UINT64 Instruction) {
	return *(int*)(Instruction + 2);
}

INT64 AutoOffset::ResovleMovRegByteSml(UINT64 Module, UINT64 Instruction) {
	return *(BYTE*)(Instruction + 2);
}

INT64 AutoOffset::ResolveTraceMovReg(UINT64 Module, UINT64 Instruction) {
	
	/* we save this cause we do the pattern scan on the call - and then the offset inside the call routine */
	Instruction -= m_InstructionOffset;

	auto JmpRva = *(int*)(Instruction + 1);

	Instruction += 5 + JmpRva;

	Instruction += m_InstructionOffset;

	return *(int*)(Instruction + 3);
}

INT64 AutoOffset::ResolveTraceMovRegByte(UINT64 Module, UINT64 Instruction) {
	
	/* we save this cause we do the pattern scan on the call - and then the offset inside the call routine */
	Instruction -= m_InstructionOffset;

	auto JmpRva = *(int*)(Instruction + 1);

	Instruction += 5 + JmpRva;

	Instruction += m_InstructionOffset;

	return *(BYTE*)(Instruction + 3);
}

bool AutoOffset::ResolveOffset(UINT64 Module, UINT64 Instruction) {

	Instruction += m_InstructionOffset;

	switch (m_Type) {

	case ScanType::MovReg:			m_Offset = ResolveMovReg(Module, Instruction);				break;
	case ScanType::MovRegByte:		m_Offset = ResolveMovRegByte(Module, Instruction);			break;
	case ScanType::MovRegXmm:		m_Offset = ResovleMovRegXmm(Module, Instruction);			break;
	case ScanType::MovRegXmmLrg:	m_Offset = ResolveMovRegXmmLrg(Module, Instruction);		break;
	case ScanType::MovRegXmmByte:	m_Offset = ResovleMovRegXmmByte(Module, Instruction);		break;
	case ScanType::MovRegXmmLrgByte:m_Offset = ResovleMovRegXmmLrgByte(Module, Instruction);	break;
	case ScanType::MovRegSml:		m_Offset = ResolveMovRegSml(Module, Instruction);			break;
	case ScanType::MovRegByteSml:	m_Offset = ResovleMovRegByteSml(Module, Instruction);		break;
	case ScanType::TraceMovReg:		m_Offset = ResolveTraceMovReg(Module, Instruction);			break;
	case ScanType::TraceMovRegByte: m_Offset = ResolveTraceMovRegByte(Module, Instruction);		break;
	case ScanType::MovCs:			m_Offset = ResolveMovCs(Module, Instruction);				break;
	case ScanType::CmpCs:			m_Offset = ResolveCmpCs(Module, Instruction);				break;
	case ScanType::FuncRVA:			m_Offset = Instruction - Module;							break;

	}

	m_Offset += m_LastOffset;

	return m_Offset;
}

bool AutoOffset::UpdateReference() {

	if (!m_Offset || !m_Reference)
		return false;

	*m_Reference = m_Offset;

	return true;
}

void AutoOffset::SetReference(INT64* Reference) {
	m_Reference = Reference;
}

void AutoOffset::SetPattern(PBYTE Pattern) {
	m_Pattern = Pattern;
}

void AutoOffset::SetMask(const char* Mask) {
	m_Mask = Mask;
}

void AutoOffset::SetSection(const char* Section) {
	m_Section = Section;
}

void AutoOffset::SetType(ScanType Type) {
	m_Type = Type;
}

void AutoOffset::SetOffset(UINT32 Offset) {
	m_InstructionOffset = Offset;
}

void AutoOffset::SetLastOffset(INT32 Offset) {
	m_LastOffset = Offset;
}

INT64 AutoOffset::GetOffset() {
	return m_Offset;
}

bool AutoOffset::Scan(UINT64 Module, PBYTE Allocated) {

	auto Instruction = Utils::PatternScan(
		Module,
		Allocated,
		m_Section,
		m_Pattern,
		m_Mask
	);

	if (!Instruction) /* oh no ! */
		return false;


	return ResolveOffset(Module, Instruction);
}

bool Updater::AllocateModule() {

	// First try the path override (set by command-line arg). When non-empty
	// we LoadLibraryA it directly — works even when DayZ isn't running, but
	// fails on Microsoft Store / Game Pass binaries (clipsp.sys denies all
	// reads of the encrypted on-disk PE). Honour --xbox to skip this path.
	if (m_PathOverride[0] && m_Platform != Platform::Xbox) {
		if (Utils::GetBaseFromPath(m_PathOverride, &m_Module, &m_Allocated))
			return true;
		printf("[UPDATER] LoadLibraryA('%s') failed; falling through to live-process scan.\n",
			m_PathOverride);
	}

	DWORD Pid = 0;
	bool havePid = Utils::GetProcessId("DayZ_x64.exe", &Pid) && Pid;

	// Steam fast path: LoadLibraryA on the unwrapped EXE in the live process.
	if (m_Platform != Platform::Xbox && havePid) {
		if (Utils::GetProcessBase(Pid, &m_Module, &m_Allocated)) {
			printf("[UPDATER] Loaded image via LoadLibraryA (pid=%lu) — Steam build.\n", Pid);
			return true;
		}
		// Fall through to NeacSafe64 only when the caller hasn't forced Steam.
		if (m_Platform == Platform::Steam) {
			printf("[UPDATER] LoadLibraryA failed and --steam was forced; aborting.\n");
			return false;
		}
		printf("[UPDATER] LoadLibraryA failed (clipsp / Game Pass build?); trying NeacSafe64.\n");
	}

	if (m_Platform == Platform::Steam) {
		printf("[UPDATER] --steam forced but DayZ_x64.exe not running.\n");
		return false;
	}

	// NeacSafe64 path — works on the clipsp-encrypted Microsoft Store /
	// Game Pass build because reads go through the FltMgr minifilter
	// channel (port \OWNeacSafePort) instead of LoadLibrary or a
	// PROCESS_VM_READ handle. The driver is loaded from %LOCALAPPDATA%\
	// GHax Labs\Driver.sys, a sibling Driver.sys next to Updater.exe, or
	// (last resort) extracted from the embedded RCDATA resource.
	if (!havePid) {
		printf("[UPDATER] DayZ_x64.exe is not running — Xbox path needs a live game.\n");
		return false;
	}
	printf("[UPDATER] Reconstructing PE via NeacSafe64 minifilter (pid=%lu)...\n", Pid);
	if (!MemImage::DumpLive("DayZ_x64.exe", &m_Module, &m_Allocated)) {
		printf("[UPDATER] NeacSafe64 live-memory dump failed.\n");
		return false;
	}
	printf("[UPDATER] Live image reconstructed at 0x%llX — proceeding with scan.\n",
		(unsigned long long)m_Module);
	if (m_SavePeTo[0]) {
		MemImage::SaveLastTo(m_SavePeTo);
	}
	return true;
}

bool Updater::DeallocateModule() {

	FreeLibrary((HMODULE)(m_Module));

	m_Module = NULL;
	m_Allocated = NULL;

	return true;
}

void Updater::SetupModbasePatterns() {
	// Modbase::FOV_Context — FOV resolver context global (0x1008CE0 in 1.29).
	// MANUAL: pattern "48 85 C0 74 31 48 8B 05 ?? ?? ?? ?? 4C 8D 05" has 150+ matches;
	// the trailing lea r8 displacement changes between builds. No unique anchor found.
	// Ghidra: search for FOV-related globals near 0x1008000 in the live build.
	// DO NOT AUTO_OFFSET — keep as ADD_OFFSET_MANUAL in Offsets.h.
	// Modbase::Network — removed, Modbase::NetworkManager already provides this
	AUTO_OFFSET(Modbase, World,
		"\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x54\x24\x00\x48\x8B\x48\x30",
		"xxx????xxxx?xxxx",
		".text", ScanType::MovCs, 0);

	// REVERTED 2026-05-19:  "Network Manager Base" pattern
	// did not match against the current DayZ build (dumper reported
	// "Failed to get offset"). The long chain of null-check derefs in
	// the pattern is brittle — the binary likely emits the same logical
	// shape with a different instruction ordering. Until a stable
	// pattern surfaces, this stays out of the working set.
	// AUTO_OFFSET(Modbase, Network,
	// 	"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x48\x00\x48\x85\xC9\x74\x00\x48\x8B\x01\x48\x8B\x48\x00\x48\x85\xC9\x74\x00\x48\x8B\x41\x00",
	// 	"xxx????xxx?xxxx?xxxxxx?xxxx?xxx?",
	// 	".text", ScanType::MovCs, 0);

	AUTO_OFFSET(Modbase, Tick,
		"\x48\x8B\x05\x00\x00\x00\x00\x0F\x57\xC9\x66\x0F\x6E\x03",
		"xxx????xxxxxxx",
		".text", ScanType::MovCs, 0);

	// Speedhack — RVA 0x348684
	// cmp qword [rip+0xCAC30C], 0  →  global at RVA 0xFF4997
	// jne +0x3B
	// lea rcx, [rsp+0x30]
	// Using FuncRVA to get the instruction address; the cheat can compute
	// the global from the cmp instruction's RIP-relative displacement.
	AUTO_OFFSET(Modbase, Speedhack,
		"\x48\x83\x3D\x00\x00\x00\x00\x00\x75\x00\x48\x8D\x4C\x24",
		"xxx????xx?xxxx",
		".text", ScanType::FuncRVA, 0);

	// OUTDATED: Modbase::ScriptContext — no replacement in .
	// AUTO_OFFSET(Modbase, ScriptContext,
	// 	"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\xD9\x4C\x8B\x88\x00\x00\x00\x00",
	// 	"xxx????xxxxxx????",
	// 	".text", ScanType::MovCs, 0);
}



void Updater::SetupNetworkPatterns() {
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x350 Xbox=0x350 — ABI confirmed identical).
	AUTO_OFFSET(Network, GameVersion, "\x48\x89\x9F\x00\x00\x00\x00\x48\x89\x9F\x58\x03\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// Updated 2026-07-15: Ping uses existing xref pattern from GameVersion - hardcode 0x33C
	// The standalone accessor is not unique enough to pattern-scan reliably.
	// Xbox and Steam both use identical struct layout for Network::Ping at 0x33C.
	// XBOX-PORTABLE 2026-07-15: Cross-platform pattern - struct init sequence.
	// mov [r?+0x308],r?; mov [r?+0x310],r?; mov [r?+0x318],r?
	AUTO_OFFSET(Network, ServerName, "\x48\x89\x00\x00\x00\x00\x00\x48\x89\x00\x10\x03\x00\x00\x48\x89", "xx?????xx?xxxxxx", ".text", ScanType::MovReg, 0);

	// NEW 2026-06-04: scoreboard (identity pointer array) lives at
	// NetworkClient + 0x18 and the slot count at +0x24. The roster walk
	// site loads both in succession:
	//   mov rax, [rbx+0x18] ; mov ecx, [rbx+0x24] ; test ecx, ecx
	// The two-instruction window (load qword + load dword + test) is rare
	// enough to anchor uniquely. We sig the qword load for Scoreboard and
	// the dword load for ScoreboardSize, each emitted by a separate
	// MovRegByte / MovRegByteSml pattern.
	// Network::Scoreboard / ScoreboardSize patterns withdrawn 2026-06-04
	// pending verification against the live binary. The 9-byte sequence
	// `48 8B 43 18 8B 4B 24 85 C9` (table+size+test) wasn't confirmed to
	// exist in DayZ_x64.exe; rather than ship a sig that might fail
	// silently, we wait for extract_all_offsets.py to surface a real one.
}

void Updater::SetupPlayerIdentityPatterns() {
	// REVERTED 2026-05-19:  "Network ID" pattern returned
	// 0x688 against the current build — far too large for a PlayerIdentity
	// field (NetworkID slots are typically < 0x100). The pattern's leading
	// `8B 8?` wildcard is too generic and matches an unrelated paired
	// load/store earlier in .text.
	// AUTO_OFFSET(PlayerIdentity, NetworkID,
	// 	"\x8B\x00\x00\x00\x00\x00\x89\x00\x00\x00\x00\x00\x48\x8B\xCB",
	// 	"x???xxx???xxxxx",
	// 	".text", ScanType::MovRegSml, 0);

	// Revived  "PlayerName":
	//   48 8D 8? ? ? 00 00 E8 ? ? ? ? 48 8D 54 24 ? 48 8B CB
	// lea rcx, [reg+disp32]; call ?; lea rdx, [rsp+disp8]; mov rcx, rbx.
	// Returned 0xB0 against current build — plausible (small entity
	// offset, right magnitude). Kept pending verification against a
	// known-good reference offset for this build.
	AUTO_OFFSET(PlayerIdentity, Name,
		"\x48\x8D\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8D\x54\x24\x00\x48\x8B\xCB",
		"xx???xxx????xxxx?xxx",
		".text", ScanType::MovReg, 0);
}

void Updater::SetupWorldPatterns() {
	AUTO_OFFSET(World, BulletList,
		"\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\xCF\x48\x03\x0C\xF8",
		"xxx????xxxxxxx",
		".text", ScanType::MovReg, 0);

	// XBOX-PORTABLE 2026-07-15: Wildcarded the second mov instruction's register bytes
	// to match both Steam (49 8B 14 06 = mov rdx, [r14+rax]) and Xbox variants.
	// The key anchor is the first mov [rbx+OFFSET] followed by any mov with [r??+rax]
	// and the subsequent cmp instruction.
	// Fixed 2026-07-16: mask length was 15, pattern is 13 bytes
	AUTO_OFFSET(World, NearEntList,
		"\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\x00\x00\x48\x3B",
		"xxx????xx??xx",
		".text", ScanType::MovReg, 0);

	// XBOX-PORTABLE 2026-07-15: Simplified pattern - just the first two instructions.
	// Steam: mov [rbx+OFFSET]; mov rcx, [r14+rax]; cmp rcx, rcx
	// Xbox may use different registers but same structure.
	// Fixed 2026-07-16: mask length was 15, pattern is 13 bytes
	AUTO_OFFSET(World, FarEntList,
		"\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\x00\x00\x48\x3B",
		"xxx????xx??xx",
		".text", ScanType::MovReg, 0);

	// World::Camera — pattern too generic, using hardcoded 0x1B8 in offsets.h
	// AUTO_OFFSET(World, Camera, ...) - commented out

	AUTO_OFFSET(World, LocalPlayer,
		"\xE8\x00\x00\x00\x00\x48\x8B\xC8\xC7\x44\x24\x00\x00\x00\x00\x00\x4C\x8D\x0D\x00\x00\x00\x00",
		"x????xxxxxx?????xxx????",
		".text", ScanType::TraceMovReg, 0);

	AUTO_OFFSET(World, LocalOffset,
		"\xE8\x00\x00\x00\x00\x48\x8B\xC8\xC7\x44\x24\x00\x00\x00\x00\x00\x4C\x8D\x0D\x00\x00\x00\x00",
		"x????xxxxxx?????xxx????",
		".text", ScanType::TraceMovReg, 16);

	// REVIVED 2026-06-03 (Ghidra-mined from DayZ_x64.exe / 1.29):
	// `lea rcx, [rbp+0x2060]; mov [rbp+0x20], r15; call ?; jmp short ?`
	// — same constructor that initialises ItemList and ItemListSize.
	// The `4C 89 7D 20 E8` (mov [rbp+0x20], r15 + call) anchor uniquely
	// picks the ItemList site. The earlier `48 89 85 ?? ?? ?? ?? 48 8D 15`
	// pattern was too generic — matched an unrelated `mov [rbp+0x1DA0]`
	// store elsewhere in .text.
	AUTO_OFFSET(World, ItemList,
		"\x48\x8D\x8D\x00\x00\x00\x00\x4C\x89\x7D\x20\xE8\x00\x00\x00\x00\xE9",
		"xxx????xxxxx????x",
		".text", ScanType::MovReg, 0);

	// NEW 2026-06-03: `mov [rbp+0x2068], r14d; mov r8d, 0x58; mov [rbp+0x2060], rax`
	// — anchors on the literal `r8d = 0x58` immediate AND the adjacent
	// ItemTable store; very unlikely to collide.
	AUTO_OFFSET(World, ItemListSize,
		"\x44\x89\xB5\x00\x00\x00\x00\x41\xB8\x58\x00\x00\x00\x48\x89\x85",
		"xxx????xxxxxxxxx",
		".text", ScanType::MovReg, 0);

	// NEW 2026-06-03: `lea rbx, [r14+0x2010]; nop; mov edi, 0x40` —
	// anchors on the unusual `0F 1F 00` (NOP w/ memory operand) +
	// `mov edi, 0x40` (xref count 64) instruction pair.
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x2010 Xbox=0x2010 — ABI confirmed identical).
	AUTO_OFFSET(World, SlowEntList, "\x49\x8D\x9E\x00\x00\x00\x00\x0F\x1F\x00\xBF\x40\x00\x00\x00", "xxx????xxxxxxxx", ".text", ScanType::MovReg, 0);

	// REVIVED 2026-06-03 (was World::GrassDensity): `mov rcx, [rsi+0xC00]; mov edx, -1`
	// — anchors on the `mov edx, 0xFFFFFFFF` (BA FF FF FF FF) that
	// follows the Grass density load.
	AUTO_OFFSET(World, Grass,
		"\x48\x8B\x8E\x00\x00\x00\x00\xBA\xFF\xFF\xFF\xFF",
		"xxx????xxxxx",
		".text", ScanType::MovReg, 0);

	// NEW 2026-06-03: `mov dword [rdi+0x2970], 0xBF32B8C3` — writes a
	// specific float constant. Anchored on the imm32 = 0xBF32B8C3,
	// extremely unlikely to collide.
	AUTO_OFFSET(World, Hour,
		"\xC7\x87\x00\x00\x00\x00\xC3\xB8\x32\xBF",
		"xx????xxxx",
		".text", ScanType::MovRegSml, 0);

	// NEW 2026-06-03: `mov dword [rdi+0x2974], 0x3E860A92` — paired with
	// Hour's init; the imm32 = 0x3E860A92 is the anchor.
	AUTO_OFFSET(World, Day,
		"\xC7\x87\x00\x00\x00\x00\x92\x0A\x86\x3E",
		"xx????xxxx",
		".text", ScanType::MovRegSml, 0);

	// NEW 2026-06-03: `mov dword [rdi+0x296C], 1.0f; mov [rdi+0x2978], edi`
	// — writes IEEE 754 1.0 (0x3F800000) to the eye accom field, followed
	// by `mov [rdi+...], edi`. The 0x3F800000 + following `44 89 BF`
	// makes this very specific.
	AUTO_OFFSET(World, EyeAccom,
		"\xC7\x87\x00\x00\x00\x00\x00\x00\x80\x3F\x44\x89\xBF",
		"xx????xxxxxxx",
		".text", ScanType::MovRegSml, 0);

	// NEW 2026-06-03: `cmp ebp, [rbx+0xE08]; jge ?; mov rax, [rbx+0xE00]`
	// — anchors on cmp + jge + load BulletList (0xE00 fixed at +11..+14).
	AUTO_OFFSET(World, BulletListSize,
		"\x3B\xAB\x00\x00\x00\x00\x7D\x00\x48\x8B\x83\x00\x0E\x00\x00",
		"xx????x?xxxxxxx",
		".text", ScanType::MovRegSml, 0);
}


void Updater::SetupHumanPatterns() {
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0xE2 Xbox=0xE2 — ABI confirmed identical).
	AUTO_OFFSET(Human, IsDead, "\xC6\x80\x00\x00\x00\x00\x02\x48\x8B\x06\xFF\x50\x30\x48\x8B\x00", "xx????xxxxxxxxx?", ".text", ScanType::MovRegSml, 0);
	// REVIVED 2026-06-03 (Ghidra-mined): `mov r8d, [rcx+0x180]; mov rbx, rcx;
	// test r8d, r8d; jz +0x2C` — load HumanType pointer + null check.
	// The `45 85 C0 74 2C` (test r8d/r8d + jz disp8) is the anchor.
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x180 Xbox=0x180 — ABI confirmed identical).
	AUTO_OFFSET(Human, HumanType, "\x44\x8B\x81\x00\x00\x00\x00\x48\x8B\xD9\x45\x85\xC0\x74\x00", "xxx????xxxxxxx?", ".text", ScanType::MovReg, 0);

	// NEW 2026-06-03: `mov dword [r14+0x194], 0x1E` — initial health
	// pool (30) write at entity construction. The imm32 = 0x0000001E
	// anchors the pattern.
	AUTO_OFFSET(Human, Quality,
		"\x41\xC7\x86\x00\x00\x00\x00\x1E\x00\x00\x00\x41\xC7\x86",
		"xxx????xxxxxxx",
		".text", ScanType::MovReg, 0);

	// REVERTED 2026-05-19:  "IsDead Flag" returned 0x430
	// against the current build — boolean fields are typically very
	// small offsets (< 0x200); 0x430 looks like a `movzx` for an
	// unrelated byte field. Pattern is too generic.
	// (Human::IsDead is already registered at the top of this function with
	// the Xbox-portable sig. Do not re-add a second AUTO_OFFSET(Human, IsDead, ...)
	// here — duplicate registration is a redefinition error from the AUTO_OFFSET
	// macro's `AutoOffset Klass##_##Name;` local declaration.)

	// Byte 17 (dst register of the trailing `mov reg,[rax]` load) wildcarded:
	// Steam emits `8B 10` (mov edx,[rax]); Xbox / Game Pass build emits
	// `8B 08` (mov ecx,[rax]). Same disp32 resolves to OFF_VisualState 0x1C8
	// on both. Verified 2026-06-25 against Steam 1.29.0.163047 + Xbox 1.29.6.0.
	AUTO_OFFSET(Human, VisualState,
		"\x48\x8B\x9F\x00\x00\x00\x00\x49\x8B\xCE\xFF\x90\x00\x00\x00\x00\x8B\x00",
		"xxx????xxxxx????x?",
		".text", ScanType::MovReg, 0);

	AUTO_OFFSET(Human, LodShape,
		"\x4C\x8B\x91\x00\x00\x00\x00\x49\x8B\xF9\x48\x63\xC2",
		"xxx????xxxxxx",
		".text", ScanType::MovReg, 0);
}


void Updater::SetupDayZInfectedPatterns() {
	// REVIVED 2026-06-03 (Ghidra-mined): triple-store at zombie entity ctor
	// `mov [rdi+0x670], r13d; mov byte [rdi+0x678], r13b; mov [rdi+0x680], r13`.
	// The sequence of (32-bit store, byte store, 64-bit store) to adjacent
	// disp32 slots is extremely specific to the zombie skeleton init site.
	// XBOX-PORTABLE 2026-07-15: Using load pattern instead of store
	// Pattern: mov rdx,[rdx+0x670]; mov rsi,rcx; call ?
	AUTO_OFFSET(DayZInfected, Skeleton,
		"\x48\x8B\x92\x00\x00\x00\x00\x48\x8B\xF1\xE8",
		"xxx????xxxx",
		".text", ScanType::MovReg, 0);
}


void Updater::SetupHumanTypePatterns() {
	// NOTE: Commented out - hardcoded E8 53 D0 2E 00 call offset won't match on Xbox.
	// AUTO_OFFSET(HumanType, CleanNameInternal, "\x48\x8D\x9F\x00\x00\x00\x00\x48\x8B\xCB\xE8\x53\xD0\x2E\x00\x48", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);

	// REVIVED 2026-06-03 (Ghidra-mined): `mov rcx, [rbx+0x70]; call ?;
	// mov rcx, [rbx+0x70]; test rcx, rcx; jz +0x0A` — double-load (re-fetch
	// after call) + null check. Disp8 = 0x70 is embedded in the pattern,
	// MovRegByte reads it at +3 of the matched instruction.
	AUTO_OFFSET(HumanType, ObjectName,
		"\x48\x8B\x4B\x70\xE8\x00\x00\x00\x00\x48\x8B\x4B\x70\x48\x85\xC9\x74\x0A",
		"xxxxx????xxxxxxxxx",
		".text", ScanType::MovRegByte, 0);
	AUTO_OFFSET(HumanType, CategoryName, "\x48\x8B\x81\x00\x00\x00\x00\x48\x8B\xF9\x0F\xB6\xF2\x48\x8D\x48\x10\x48\x85\xC0\x75\x07\x48\x8D\x0D\x00\x00\x00\x00\x48\x8D\x15\x00\x00\x00\x00\x48\x89\x6C\x24\x00\xE8\x00\x00\x00\x00", "xxx????xxxxxxxxxxxxxxxxxx????xxx????xxxx?x????", ".text", ScanType::MovReg, 0);

	// NEW 2026-06-03 (Ghidra-mined): `mov rcx, [rbx+0x518]; call ?; mov rcx, [rbx+0x500]; call ?`
	// — display-name + internal-name double-load pair. Second disp32
	// = 0x500 is hard-coded into the pattern to disambiguate.
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x518 Xbox=0x518 — ABI confirmed identical).
	AUTO_OFFSET(HumanType, CleanName, "\x48\x8B\x8B\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x8B\x00\x05\x00\x00", "xxx????x????xxxxxxx", ".text", ScanType::MovReg, 0);
}

void Updater::SetupDayZLocalPatterns() {
	// Removed 2026-06-03: duplicate DayZInfected::Skeleton entry that
	// overwrote SetupDayZInfectedPatterns' version in the m_Scans map.
	// Real DayZInfected::Skeleton sig now lives in SetupDayZInfectedPatterns.
}

void Updater::SetupDayZPlayerPatterns() {
	// REVIVED 2026-06-03 (Ghidra-mined): `mov [rbx+0x7E0], rdi; mov [rbx+0x28], edi;
	// mov dword [rbx+0x410], -1` — skeleton + sub-field + sentinel init.
	// The `89 7B 28 48 C7 83` (next store + sentinel) is the anchor.
	AUTO_OFFSET(DayZPlayer, Skeleton,
		"\x48\x89\xBB\x00\x00\x00\x00\x89\x7B\x28\x48\xC7\x83",
		"xxx????xxxxxx",
		".text", ScanType::MovReg, 0);

	// OUTDATED: DayZPlayer::NetworkID
	// AUTO_OFFSET(DayZPlayer, NetworkID,
	// 	"\x41\x8B\x9E\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xC8",
	// 	"xxx????x????xxx",
	// 	".text", ScanType::MovReg, 0);

	AUTO_OFFSET(DayZPlayer, Inventory,
		"\x48\x8B\x8B\x00\x00\x00\x00\x48\x8B\x01\xFF\x90\x00\x00\x00\x00\xEB\x02",
		"xxx????xxxxx????xx",
		".text", ScanType::MovReg, 0);
}


void Updater::SetupDayZPlayerInventoryPatterns() {

	AUTO_OFFSET(DayZPlayerInventory, Hands, "\x48\x8B\x8B\x00\x00\x00\x00\x48\x8B\xF8\x48\x85\xC9", "xxx????xxxxxx", ".text", ScanType::MovReg, 0);

}

void Updater::SetupInventoryItemPatterns() {

	AUTO_OFFSET(InventoryItem, ItemInventory, "\x48\x8B\x8B\x00\x00\x00\x00\x48\x8B\x01\xFF\x90\x00\x00\x00\x00\xEB\x02", "xxx????xxxxx????xx", ".text", ScanType::MovReg, 0);


}

void Updater::SetupWeaponPatterns() {
	AUTO_OFFSET(Weapon, AmmoMagCount, "\x39\x9F\x00\x00\x00\x00\x76\x79\x4C\x8B\x97\xA0\x06\x00\x00\x44", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Weapon, AmmoCapacityB, "\x44\x3B\x82\x00\x00\x00\x00\x0F\x83\xF5\x03\x00\x00\x41\x8B\xD0", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// Weapon::AmmoCapacityA at +0x6B0 — ammo capacity A field.
	// Pattern: mov [rax+disp32], r10d; mov [rax+disp32], r10d (consecutive stores)
	// Wildcarded offsets to match any consecutive store sequence.
	// Updated 2026-07-15: Fixed opcode and anchored on 0x6B0 offset
	AUTO_OFFSET(Weapon, AmmoCapacityA, "\x4C\x89\x80\xB0\x06\x00\x00\x4C\x89\x80\xC0\x06\x00\x00", "xxxxxxxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Weapon, ChamberedPtr, "\x49\x89\xB7\x00\x00\x00\x00\x89\x5A\x0C\x41\x89\x9F\xB8\x01\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// OUTDATED: Weapon::MuzzleCount
	// AUTO_OFFSET(Weapon, MuzzleCount,
	// 	"\x3B\x98\x00\x00\x00\x00\x73\x00\x8B\xCB",
	// 	"xx????x?xx",
	// 	".text", ScanType::MovRegSml, 0);

	AUTO_OFFSET(Weapon, WeaponInfoSize,
		"\x3B\x91\x00\x00\x00\x00\x73\x00\x8B\xCA",
		"xx????x?xx",
		".text", ScanType::MovRegSml, 0);

	// OUTDATED: Weapon::WeaponIndex
	// AUTO_OFFSET(Weapon, WeaponIndex,
	// 	"\x48\x8B\xCF\x48\x63\x9F\x00\x00\x00\x00\xFF\x90\x00\x00\x00\x00",
	// 	"xxxxxx????xx????",
	// 	".text", ScanType::MovReg, 3);

	AUTO_OFFSET(Weapon, WeaponInfoTable,
		"\x48\x8B\x81\x00\x00\x00\x00\x44\x8B\xC2\x49\xC1\xE0\x08",
		"xxx????xxxxxxx",
		".text", ScanType::MovReg, 0);
}


void Updater::SetupWeaponInventoryPatterns() {

	// OUTDATED: WeaponInventory::MagazineRef
	// AUTO_OFFSET(WeaponInventory, MagazineRef, "\x48\x8B\xB9\x00\x00\x00\x00\x48\x8B\xE9\x8B\xB1\x00\x00\x00\x00", "xxx????xxxxx????", ".text", ScanType::MovReg, 0);

}

void Updater::SetupMagazinePatterns() {

	// OUTDATED: Magazine::MagazineType
	// AUTO_OFFSET(Magazine, MagazineType, "\x4C\x8B\xB1\x00\x00\x00\x00\x32\xDB\x0F\x29\x74\x24\x00", "xxx????xxxxxx?", ".text", ScanType::MovReg, 0);

	// REVIVED 2026-06-03 (Ghidra-mined): `mov rax, [rbx+0x3B0]; mov rcx, [rax+0x08];
	// test rcx, rcx; jz +0x18; lea rax, [rcx+0x58]` — load mag ptr, deref next field,
	// null-check, then lea to ammo slot. Very distinctive shape.
	// XBOX-PORTABLE 2026-07-15: Uses Steam pattern (48 8B 83), Xbox uses hardcoded 0x3B0.
	AUTO_OFFSET(Magazine, AmmoCount,
		"\x48\x8B\x83\x00\x00\x00\x00\x48\x8B\x48\x08\x48\x85\xC9\x74\x18\x48\x8D\x81\x58",
		"xxx????xxxxxxxxxxxxx",
		".text", ScanType::MovReg, 0);

	// NEW 2026-06-03: `cmp dword [rax+0x3A4], 0; jle ?; mov r8, rsi; lea rcx, [rbp+0x350]`
	// — capacity check + branch + setup-call sequence. The `lea rcx, [rbp+0x350]`
	// (48 8D 8D 50 03 ...) is the anchor.
	AUTO_OFFSET(Magazine, MaxAmmo,
		"\x83\xB8\x00\x00\x00\x00\x00\x7E\x00\x4C\x8B\xC6\x48\x8D\x8D\x50\x03",
		"xx????xx?xxxxxxxx",
		".text", ScanType::MovRegSml, 0);
}

void Updater::SetupAmmoTypePatterns() {
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x3A4 Xbox=0x3A4 — ABI confirmed identical).
	AUTO_OFFSET(AmmoType, Dispersion, "\xF3\x0F\x11\x8B\x00\x00\x00\x00\x44\x89\x00\xA8\x03\x00\x00\x66", "xxxx????xx?xxxxx", ".text", ScanType::MovRegXmm, 0);
	// NOTE: Steam/Xbox have different modrm bytes. Using Steam-only pattern.
	AUTO_OFFSET(AmmoType, AirFriction, "\x39\x98\x00\x00\x00\x00\x76\x3A\x66\x0F\x1F\x84\x00\x00\x00\x00", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(AmmoType, InitSpeed, "\x49\x8D\xBF\x00\x00\x00\x00\x66\x0F\x1F\x84\x00\x00\x00\x00\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// OUTDATED: AmmoType::InitSpeed
	// AUTO_OFFSET(AmmoType, InitSpeed,
	// 	"\x45\x0F\x2F\x8F\x00\x00\x00\x00\x0F\x83\x00\x00\x00\x00",
	// 	"xxxx????xx????",
	// 	".text", ScanType::MovRegXmm, 0);

	// OUTDATED: AmmoType::AirFriction
	// AUTO_OFFSET(AmmoType, AirFriction,
	// 	"\xF3\x45\x0F\x10\x87\x00\x00\x00\x00\x48\x8D\x55\xC7",
	// 	"xxxxx????xxxx",
	// 	".text", ScanType::MovRegXmmLrg, 0);
}


void Updater::SetupSkeletonPatterns() {
	// OUTDATED: Skeleton::AnimClass1
	// AUTO_OFFSET(Skeleton, AnimClass1,
	// 	"\x48\x8B\x8F\x00\x00\x00\x00\x0F\xB6\xD0\x48\x81\xC1\x00\x00\x00\x00",
	// 	"xxx????xxxxxx????",
	// 	".text", ScanType::MovReg, 0);

	AUTO_OFFSET(Skeleton, AnimClass2,
		"\xE8\x00\x00\x00\x00\xEB\x12\x4C\x8B\xCB\x89\x7C\x24\x20\x4D\x8B\xC4\x49\x8B\xCE",
		"x????xxxxxxxxxxxxxxx",
		".text", ScanType::TraceMovRegByte, 0);
}


void Updater::SetupAnimClassPatterns() {
	// OUTDATED: AnimClass::MatrixArray
	// AUTO_OFFSET(AnimClass, MatrixArray,
	// 	"\x49\x8B\xBE\x00\x00\x00\x00\x83\xFA\xFF\x74\x00",
	// 	"xxx????xxxx?",
	// 	".text", ScanType::MovReg, 0);
}


void Updater::SetupCameraPatterns() {

	// Camera::ViewMatrix — three-consecutive-movss shape. NOT Xbox-portable:
	// the same shape exists at multiple unrelated sites on Xbox and the
	// first-match wins picks a different one (Steam=0x4, Xbox-false=0x24).
	// Steam value 0x4 is the engine ABI offset and applies to both builds;
	// trust the Steam dump for this one until a uniquely-disambiguating sig
	// is found. The v15 cheat does not consume this sig — its camera offsets
	// are resolved through a different path (Modbase::Landscape/ScopeFovCtx).
	AUTO_OFFSET(Camera, ViewMatrix, "\xF3\x0F\x10\x40\x00\xF3\x0F\x10\x50\x00\xF3\x0F\x10\x58\x00", "xxxx?xxxx?xxxx?", ".text", ScanType::MovRegXmmByte, 0);

	// Camera::ProjectionD1 at +0xD0 — projection divisor for W2S.
	// Community signature: "48 8B B7 D0 00 00 00 48 85 F6"
	// mov rsi,[rdi+0xD0]; test rsi,rsi — unique load/null-check sequence.
	AUTO_OFFSET(Camera, ProjectionD1, "\x48\x8B\xB7\xD0\x00\x00\x00\x48\x85\xF6", "xxxxxxxxxx", ".text", ScanType::MovReg, 0);

	// Camera::ViewportSize at +0x58 — viewport dimensions (Vec2).
	// Pattern from struct initialization site: mov [reg+0x58], reg; mov [reg+0x5C], reg
	// Using consecutive stores to viewport width (0x58) and height (0x5C) as anchor.
	// Note: Small offsets like 0x58 are common; this pattern may need refinement.
	// For now, rely on hardcoded value in Offsets.h if this pattern fails.
	// AUTO_OFFSET(Camera, ViewportSize, ...) — pattern too generic, keep hardcoded

	// OUTDATED: Camera::ViewPortMatrix
	// AUTO_OFFSET(Camera, ViewPortMatrix, "\xF3\x0F\x11\x4E\x00\x66\x0F\x6E\xC1", "xxxx?xxxx", ".text", ScanType::MovRegXmmByte, 0);

	// OUTDATED: Camera::ViewProjection
	// AUTO_OFFSET(Camera, ViewProjection, "\x0F\x11\x86\x00\x00\x00\x00\x0F\x10\x44\x24\x00\x0F\x11\x86\x00\x00\x00\x00\x0F\x10\x44\x24\x00\x0F\x11\x86\x00\x00\x00\x00\x48\x8B\x06", "xxx????xxxx?xxx????xxxx?xxx????xxx", ".text", ScanType::MovRegByte, 0);

}

void Updater::SetupVisualStatePatterns() {

	// Old sig landed on a vec3 load at +0x4 (returns 0x4) but 1.29 truth is
	// +0x8 (visual_state::transform). New anchor: 0x1400A8C68 —
	//   movss   xmm2, [rcx+0x8]
	//   subss   xmm3, [r8]
	//   subss   xmm2, [r8+0x8]
	// — a transform-delta calc against a VisualState pointer. Unique in
	// .text; first disp8 is the field we want, so MovRegXmmByte reads byte+4.
	AUTO_OFFSET(VisualState, Transform, "\xF3\x0F\x10\x51\x00\xF3\x41\x0F\x5C\x18\xF3\x41\x0F\x5C\x50\x08", "xxxx?xxxxxxxxxxx", ".text", ScanType::MovRegXmmByte, 0);
	// VisualState::InverseTransform at +0xA4 — inverse transform matrix offset.
	// Pattern: mov [rdx+disp32], rax followed by mov rax,[rax]
	// Wildcarded offset to match any inverse transform access.
	AUTO_OFFSET(VisualState, InverseTransform, "\x48\x89\x80\x00\x00\x00\x00\x48\x8B\x01", "xx????xxxx", ".text", ScanType::MovReg, 0);

	// NEW v16: VisualState::Velocity at +0x54.
	// REMOVED: pattern matched wrong instruction (resolved 0xB8 instead of 0x54).
	// The three-consecutive-movss shape exists at multiple sites in the binary;
	// the first match is NOT the velocity read. Requires Ghidra analysis of the
	// actual interpolation function to find a unique anchor.

	// NEW v16: VisualState::Direction at +0x20 (forward vector).
	// REMOVED: pattern matched wrong instruction (resolved 0x2C instead of 0x20).
	// The three-consecutive-movss-byte shape is too common in camera/transform code.
}



// ═══════════════════════════════════════════════════════════════════════════
//  v16 EXTENDED PATTERN GROUPS
//  New signature categories covering: Entity extended, Camera extended,
//  DamageManager, InputController, Weather, Grass, World extended,
//  Network extended, Weapon extended, AmmoType extended, Function RVAs,
//  Modbase extended, Freecam, HumanCommand, PhysicsBody
// ═══════════════════════════════════════════════════════════════════════════

void Updater::SetupEntityExtendedPatterns() {
	// Entity::Owner at +0xA0 — CONFIRMED 0xA0, kept.
	AUTO_OFFSET(Entity, Owner,
		"\x48\x8B\x00\xA0\x00\x00\x00\x48\x85\xC0\x0F\x84",
		"xx?xxxxxxxxx",
		".text", ScanType::MovReg, 0);

	// Entity::SortObject at +0x228 — CONFIRMED 0x228, kept.
	AUTO_OFFSET(Entity, SortObject,
		"\x48\x8B\x00\x28\x02\x00\x00\x48\x85\xC0",
		"xx?xxxxxxx",
		".text", ScanType::MovReg, 0);

	// Entity::Stamina at +0x6A4 — CONFIRMED 0x6A4, kept.
	AUTO_OFFSET(Entity, Stamina,
		"\xF3\x0F\x10\x00\xA4\x06\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// Entity::SprintFlag at +0x3AD — byte, sprinting state.
	// Scanner4 found clean prologue at RVA 0x5E7444:
	//   push rbx; sub rsp,0x20; movsx edx, byte [rcx+0x3AD]; ...
	// 0F BE 91 AD030000 = movsx edx, byte [rcx+0x3AD] (mod=10/disp32, reg=edx, rm=rcx)
	// m_InstructionOffset=6 skips the 6-byte prologue to land on 0F BE.
	// MovReg resolver reads *(int*)(Instruction+3) = disp32 at byte 9 from match = 0x3AD.
	// ModRM byte (byte 8) wildcarded to accept any base register.
	AUTO_OFFSET(Entity, SprintFlag,
		"\x40\x53\x48\x83\xEC\x20\x0F\xBE\x00\x00\x00\x00\x00\x48\x8B\xD9\x83\xEA\x01",
		"xxxxxxxx?????xxxxxx",
		".text", ScanType::MovReg, 6);

	// Entity::isHandItemValid at +0x1CC — hand item validity flag.
	// Updated 2026-09-13: Ghidra analysis found unique pattern at RVA 0x1B36BA:
	//   mov edx,[rcx+0x1CC]; lea r8,[rsp+0x38]; mov rbx,rcx; mov ...
	// The consecutive load + lea + mov rbx provides unique anchoring.
	AUTO_OFFSET(Entity, isHandItemValid,
		"\x8B\x91\xCC\x01\x00\x00\x4C\x8D\x44\x24\x38\x48\x8B\xD9\x48\x8B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::MovRegSml, 0);

	// REMOVED: Entity::Parent (+0x88), Entity::ModelName (+0x78) —
	// patterns match wrong instruction sites.
}

void Updater::SetupCameraExtendedPatterns() {
	// REMOVED: All Camera extended patterns — too generic or don't match.
	// Camera::StateFlags (0x1A8) — scanner found `test byte [rbx+0x1A8], 0x14`
	// but the pattern doesn't match in the LoadLibraryA-loaded image.
	// Camera::Position (0x2C), ProjectionD1 (0xD0), AspectRatio (0x6C),
	// FOV_TermA (0x4C) — all match wrong instruction sites (too common).
}

void Updater::SetupDamageManagerPatterns() {
	// REMOVED: DamageManager::GlobalHealth, InitFlags — patterns don't match
	// the binary (instruction forms differ from expected).
}

void Updater::SetupInputControllerPatterns() {
	// REMOVED: InputController::AimChangeX, AimChangeY, MoveSpeed, RaiseFlag —
	// patterns don't match (code at the expected site uses different instructions).
}

void Updater::SetupWeatherPatterns() {
	// REMOVED: Weather::StormDensity, StormThreshold — patterns don't match.
}

void Updater::SetupGrassRendererPatterns() {
	// REMOVED: GrassRenderer::DistMax, LOD — patterns don't match.
}

void Updater::SetupWorldExtendedPatterns() {
	// REMOVED: World::SlowEntCount, ItemList2, TimeMultiplier, MissionHeader —
	// patterns don't match.
}

void Updater::SetupNetworkExtendedPatterns() {
	// Network::ScoreboardSize at +0x24 — CONFIRMED 0x24, kept.
	AUTO_OFFSET(Network, ScoreboardSize,
		"\x8B\x4B\x24\x85\xC9\x74",
		"xxxxxx",
		".text", ScanType::MovRegByteSml, 0);

	// Network::ThirdPersonFlag at +0x9C — CONFIRMED 0x9C, kept.
	AUTO_OFFSET(Network, ThirdPersonFlag,
		"\x89\x00\x9C\x00\x00\x00\x8B\x00\xA0\x00\x00\x00",
		"x?xxxxx?xxxx",
		".text", ScanType::MovRegSml, 0);

	// REMOVED: Network::ScoreboardTable, MissionHeaderPtr — patterns don't match.
}

void Updater::SetupWeaponExtendedPatterns() {
	// Weapon::InitSpeedMultiplier at +0x960 — CONFIRMED 0x960, kept.
	AUTO_OFFSET(Weapon, InitSpeedMultiplier,
		"\xF3\x0F\x11\x00\x60\x09\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// REMOVED: Weapon::MuzzleCount — pattern doesn't match.
}

void Updater::SetupAmmoTypeExtendedPatterns() {
	// v16-fix: All AmmoType patterns — wildcard ModRM byte to accept any
	// base register, lock disp32 to the expected offset value.

	// AmmoType::TimeToLive at +0x3D8 — float.
	AUTO_OFFSET(AmmoType, TimeToLive,
		"\xF3\x0F\x10\x00\xD8\x03\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// AmmoType::CoefGravity at +0x3BC — float (CONFIRMED 0x3BC, not changed).
	AUTO_OFFSET(AmmoType, CoefGravity,
		"\xF3\x0F\x10\x80\xBC\x03\x00\x00",
		"xxxxxxxx",
		".text", ScanType::MovRegXmm, 0);

	// AmmoType::TracerScale at +0x408 — float.
	AUTO_OFFSET(AmmoType, TracerScale,
		"\xF3\x0F\x10\x00\x08\x04\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// AmmoType::DamageBarrel at +0x418 — float.
	AUTO_OFFSET(AmmoType, DamageBarrel,
		"\xF3\x0F\x10\x00\x18\x04\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// AmmoType::JamChance at +0x420 — float.
	AUTO_OFFSET(AmmoType, JamChance,
		"\xF3\x0F\x10\x00\x20\x04\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// AmmoType::ProjectileCount at +0x3D0 — REMOVED (pattern doesn't match).

	// AmmoType::SimulationStep at +0x3B8 — float.
	AUTO_OFFSET(AmmoType, SimulationStep,
		"\xF3\x0F\x10\x00\xB8\x03\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// AmmoType::TypicalSpeed at +0x398 — float.
	AUTO_OFFSET(AmmoType, TypicalSpeed,
		"\xF3\x0F\x10\x00\x98\x03\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);

	// AmmoType::MaxLeadSpeed at +0x394 — float.
	AUTO_OFFSET(AmmoType, MaxLeadSpeed,
		"\xF3\x0F\x10\x00\x94\x03\x00\x00",
		"xxx?xxxx",
		".text", ScanType::MovRegXmm, 0);
}

void Updater::SetupFunctionRVAPatterns() {
	// Function RVAs use ScanType::FuncRVA which reports the match address
	// directly as the RVA (no disp32 decoding). The pattern matches the
	// function prologue and the RVA = pattern_match_address - module_base.
	// Verified against DayZ_x64.exe 1.29.0.163047 (Steam) via Scanner.exe.

	// SetObjectMaterial — RVA 0x478BE0 (VA 0x140478BE0)
	// Prologue: push rbp; push rsi; push rdi; sub rsp,0x40; mov esi,edx;
	//           mov rbp,rcx; test r8,r8; je +0x1C5
	// 16-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, SetObjectMaterial,
		"\x40\x55\x56\x57\x48\x83\xEC\x40\x8B\xF2\x48\x8B\xE9\x4D\x85\xC0",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// PhysicsRaycast (Landscape::ObjectCollisionLine) — RVA 0x912EC0
	// Prologue: mov rax,rsp; mov [rax+8],rbx; mov [rax+18h],rsi;
	//           mov [rax+20h],rdi; push rbp; push r12; push r13; push r14;
	//           push r15; lea rbp,[rsp-2Fh]
	// 28-byte prologue is unique.
	AUTO_OFFSET(Functions, PhysicsRaycast,
		"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x18\x48\x89\x78\x20\x55\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x68\xD1",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// FindClassByName (Enfusion Script VM) — RVA 0x31F850
	// Prologue: sub rsp,38h; movzx r9d,r8b; mov r8,rdx; lea rdx,[rsp+20h];
	//           call ...
	// 17-byte prologue is unique.
	AUTO_OFFSET(Functions, FindClassByName,
		"\x48\x83\xEC\x38\x45\x0F\xB6\xC8\x4C\x8B\xC2\x48\x8D\x54\x24\x20\xE8",
		"xxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === 2026-07-12 batch: Ghidra ChamsBypass analysis ===

	// SetMaterialSlot — RVA 0x478B70
	// Prologue: push rbx; sub rsp,0x20; mov rbx,rcx; test edx,edx;
	//           jae +0x41; cmp [rcx+0x560],edx; ...
	// 16-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, SetMaterialSlot,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x85\xD2\x78\x41\x3B\x91\x60",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// GetObjectMaterial — RVA 0x4737A0
	// Prologue: test edx,edx; jae +0x31; cmp [rcx+0x560],edx;
	//           jae +0x29; mov rax,[rcx+0x558]; movsxd rdx,edx; ...
	// 16-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, GetObjectMaterial,
		"\x85\xD2\x78\x31\x3B\x91\x60\x05\x00\x00\x7D\x29\x48\x8B\x81\x58",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// LoadMaterial — RVA 0x969A90
	// Prologue: push rbp; push rsi; push r14; sub rsp,0x30; mov r14,rcx;
	//           mov [rsp+0x58],rbx; xor esi,esi; ...
	// 16-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, LoadMaterial,
		"\x40\x55\x56\x41\x56\x48\x83\xEC\x30\x4C\x8B\xF1\x48\x89\x5C\x24",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisualState accessor — RVA 0x704150 (1.29)
	// Prologue: lea rax,[rip+X]; ret; (CC padding)
	// Returns pointer to global 0x100FC40. Wildcard LEA displacement.
	AUTO_OFFSET(Functions, VisualStateAccessor,
		"\x48\x8D\x05\xE9\xBA\x90\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxx????xxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Dirty/invalidate func — RVA 0x716AA0
	// Prologue: push rdi; push r14; push r15; sub rsp,0x30; mov r14,rcx;
	//           mov rdi,rdx; lea rcx,[rdx+0xA8]; ...
	// 16-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, DirtyInvalidate,
		"\x40\x57\x41\x56\x41\x57\x48\x83\xEC\x30\x4C\x8B\xF1\x48\x8B\xFA",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Refcount release — RVA 0x33B010 (updated 2026-07-16 for 1.29)
	// Prologue: test rcx,rcx; je +0x23; push rbx; sub rsp,0x20;
	//           cmp byte [rip+...],0; ...
	// Wildcard the cmp displacement
	AUTO_OFFSET(Functions, RefcountRelease,
		"\x48\x85\xC9\x74\x23\x53\x48\x83\xEC\x20\x80\x3D\x4F\x83\xCB\x00",
		"xxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// Material table allocator — RVA 0x473360
	// Prologue: sub rsp,0x28; call +0x37; lea rcx,[rip+0xB94F88];
	//           xor edx,edx; cmp rax,rcx; ...
	// 16-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, MaterialTableAlloc,
		"\x48\x83\xEC\x28\xE8\x87\x7D\x9A\x00\x48\x8D\x05\x60\x12\xD0\x00",
		"xxxxx????xxx????",
		".text", ScanType::FuncRVA, 0);

	// Material table find2 — RVA 0x4752F0
	// Prologue: mov [rsp+0x10],rsi; push rdi; sub rsp,0x20; mov rsi,rcx;
	//           mov rcx,rdx; call ...
	// 16B has 2 matches; 24-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, MaterialTableFind2,
		"\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xF1\x48\x8B\xCA\xE8\xEB\x50\x4F\x00\x48\x8B\xF8",
		"xxxxxxxxxxxxxxxxx????xxx",
		".text", ScanType::FuncRVA, 0);

	// String allocator — RVA 0x2B5B10
	// Prologue: mov [rsp+8],rbx; push rdi; sub rsp,0x150; mov rdi,rdx;
	//           mov rbx,rcx; test rdx,rdx; jz +0xC0; ...
	// 16B has 2 matches; 24-byte prologue is unique in .text.
	AUTO_OFFSET(Functions, StringAllocator,
		"\x48\x89\x5C\x24\x08\x57\x48\x81\xEC\x50\x01\x00\x00\x48\x8B\xFA\x48\x8B\xD9\x48\x85\xD2\x0F\x84",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === 2026-07-13 batch: Ghidra/Scanner4 function RVAs ===

	// LoadOrCreateMaterial — RVA 0x96BD30
	// Entry: cmp dword [rcx+0x58],0; je +0xFEEE; ret; (int3 pad)
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, LoadOrCreateMaterial,
		"\x83\x79\x58\x00\x0F\x84\x36\xFE\xFF\xFF\xC3\xCC\xCC\xCC\xCC\xCC",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// NetworkStateDispatcher — RVA 0x0C3A80
	// Entry: cmp al,-1; dec eax; mov [rdi+4],eax; mov byte [rdi+0x14],1; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, NetworkStateDispatcher,
		"\x3C\xFF\xFF\xFF\x89\x47\x04\xC6\x47\x14\x01\x83\xF8\x04\x0F\x84",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// SendWrapper1 — RVA 0x0AB9180
	// Prologue: mov [rsp+8],rbx; mov [rsp+0x10],rsi; push rdi; sub rsp,0x30;
	//           mov rax,[rcx+0x10]; mov rbx,rcx; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, SendWrapper1,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// SendWrapper2 — RVA 0x0AB9D00
	// Prologue: mov [rsp+8],rbx; mov [rsp+0x18],rsi; push rdi; sub rsp,0x30;
	//           mov rax,[rcx+0x10]; mov rbx,rcx; xor esi,esi; mov ecx,edx; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, SendWrapper2,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MaterialReloadHelper — RVA 0x46CDB0
	// Entry: mov eax,[rcx+0x70]; mov r8,rdx; mov rdx,rcx; mov ecx,2;
	//        sub eax,[r8+0x40]; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, MaterialReloadHelper,
		"\x8B\x41\x70\x4C\x8B\xC2\x48\x8B\xD1\xB9\x02\x00\x00\x00\x41\x2B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DirtyInvalidateHelper1 — RVA 0x465D70
	// Prologue: push rdi; sub rsp,0x20; inc dword [rcx+8]; mov rdi,rcx;
	//           mov rax,[rcx]; mov rcx,[rax+8]; test rcx,rcx; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, DirtyInvalidateHelper1,
		"\x40\x57\x48\x83\xEC\x20\xFF\x41\x08\x48\x8B\xF9\x48\x8B\x01\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DirtyInvalidateHelper2 — RVA 0x45B0F0
	// Prologue: mov [rsp+0x18],rbx; mov [rsp+0x20],rsi; push r14; sub rsp,0x20;
	//           mov rbx,rdx; mov r14,rcx; test rdx,rdx; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, DirtyInvalidateHelper2,
		"\x48\x89\x5C\x24\x18\x48\x89\x74\x24\x20\x41\x56\x48\x83\xEC\x20",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DirtyInvalidateHelper3 — RVA 0x45BDC0
	// Prologue: mov [rsp+0x10],rbx; push rsi; sub rsp,0x20; mov rsi,rdx;
	//           mov rbx,rcx; cmp rdx,rcx; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, DirtyInvalidateHelper3,
		"\x48\x89\x5C\x24\x10\x56\x48\x83\xEC\x20\x48\x8B\xF2\x48\x8B\xD9",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DirtyInvalidateHelper4 — RVA 0x46B280
	// Prologue: mov [rsp+0x18],rsi; push rdi; sub rsp,0x20; mov rsi,rcx;
	//           mov ecx,[rcx+8]; inc ecx; mov rax,[rdx]; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, DirtyInvalidateHelper4,
		"\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x48\x8B\xF1\x8B\x49\x08",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RefcountDecHelper — RVA 0x08B0C0
	// Prologue: push rbx; sub rsp,0x20; mov rax,[rcx]; mov rbx,rcx;
	//           test rax,rax; je +0x71; mov eax,[rax]; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, RefcountDecHelper,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\x01\x48\x8B\xD9\x48\x85\xC0\x74",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// InnerDestructor — RVA 0x9F0D00 (updated 2026-07-16 for 1.29)
	// Entry: test rcx,rcx; jne +...; ret; (int3 pad)
	// Wildcard the jne displacement
	AUTO_OFFSET(Functions, InnerDestructor,
		"\x48\x85\xC9\x0F\x85\x67\xC2\x95\xFF\xC3\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxxxx????xxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MaterialArenaAlloc — RVA 0xBE7200
	// Prologue: push rbx; sub rsp,0x20; mov rbx,rcx; jmp +0xF; mov rcb,rax;
	//           call +0x6E5B; test eax,eax; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, MaterialArenaAlloc,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xEB\x0F\x48\x8B\xCB\xE8\x5B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MaterialResolve — RVA 0x968480
	// Prologue: mov [rsp+8],rbx; mov [rsp+0x10],rbp; push rsi; push rdi;
	//           push r12; push r13; push r14; push r15; sub rsp,0x20; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, MaterialResolve,
		"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x56\x57\x41\x54\x41\x56",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// BufferGrow — RVA 0x0E26A0
	// Prologue: mov [rsp+8],rbx; mov [rsp+0x10],rbp; mov [rsp+0x18],rsi;
	//           push rdi; sub rsp,0x20; mov rbp,rcx; mov rbx,rcx; ...
	// 16-byte pattern is unique in .text.
	AUTO_OFFSET(Functions, BufferGrow,
		"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === 2026-07-13: ObjectVisualState VTable function RVAs (Ghidra) ===
	// All patterns verified unique against the loaded DayZ_x64.exe 1.29 PE.

	// VT1[0] — RVA 0x7B7750 (updated 2026-07-16 for 1.29)
	// push rbx; sub rsp,0x20; lea rax,[rip+...]; mov rbx,rcx; ...
	// Wildcard the lea displacement
	AUTO_OFFSET(Functions, OVS_VT1_Construct,
		"\x40\x53\x48\x83\xEC\x20\x48\x8D\x05\x0B\xF5\x44\x00\x48\x8B\xD9",
		"xxxxxxxxx????xxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[1] — RVA 0x9309F0 — field copier (mov eax,[rdx]; mov [rcx+0x2C],eax; ...)
	// 16B has 2 matches (0x3FD850, 0x9309F0); 18B is unique (includes trailing ret).
	AUTO_OFFSET(Functions, OVS_VT1_CopyFields,
		"\x8B\x02\x89\x41\x2C\x8B\x42\x04\x89\x41\x30\x8B\x42\x08\x89\x41\x34\xC3",
		"xxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[4] — RVA 0x930D20 — init+copy (mov [rsp+8],rbx; ... sub rsp,0x30; mov eax,[rdx]; ...)
	// 16B would collide with MaterialResolve at byte 12; 24B is unique.
	AUTO_OFFSET(Functions, OVS_VT1_InitCopy,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x8B\x02\x0F\x57\xC0\x89\x41\x08\x48",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[5] — RVA 0x930D20 (updated 2026-07-16 for 1.29)
	// push rbx; sub rsp,0x20; mov rbx,rcx; add rcx,8; call ...; ...
	// Wildcard the call displacement
	AUTO_OFFSET(Functions, OVS_VT1_InitZero,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x83\xC1\x08\xE8\x6E\xC7",
		"xxxxxxxxxxxxxx??",
		".text", ScanType::FuncRVA, 0);

	// VT1[8] — RVA 0x9308A0 — transform copy (sub rsp,0x30; movaps [rsp+0x20],xmm6; ...)
	// 16B has 2 matches (0x9010A0, 0x9308A0); 18B is unique (add rcx,8 disambiguates).
	AUTO_OFFSET(Functions, OVS_VT1_TransformCopy,
		"\x40\x53\x48\x83\xEC\x30\x48\x8B\xD9\x0F\x29\x74\x24\x20\x48\x83\xC1\x08",
		"xxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[9] — RVA 0x923C20 — comparison (comiss xmm0,[rcx+0x3C]; lea rdx,[rcx+8]; ...)
	// 16B unique (comiss + lea + mov rcx,rbx shape).
	AUTO_OFFSET(Functions, OVS_VT1_Compare,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xDA\x0F\x57\xC0\x0F\x2F\x41\x3C",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[10] — RVA 0x926630 — full init (push rbp; push rsi; push rdi; push r14; push r15; ...)
	// 16B has 4 matches; 17B is unique (lea rbp,[rsp-0x10] byte F0 disambiguates).
	AUTO_OFFSET(Functions, OVS_VT1_FullInit,
		"\x48\x89\x5C\x24\x18\x55\x56\x57\x41\x56\x41\x57\x48\x8D\x6C\x24\xF0",
		"xxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[11] — RVA 0x7B7AA0 (updated 2026-07-16 for 1.29)
	// sub rsp,0x78; movaps xmm0,[rcx+8]; lea rax,[rip+...]; ...
	// Wildcard the lea displacement
	AUTO_OFFSET(Functions, OVS_VT1_Subtract,
		"\x48\x83\xEC\x78\x0F\x10\x41\x08\x48\x8D\x05\x81\xC1\x54\x00\xF3",
		"xxxxxxxxxxx????x",
		".text", ScanType::FuncRVA, 0);

	// VT1[12] — RVA 0x7B7224 — small sub thunk (sub rcx,0x40; jmp ...; int3; sub rcx,0x10; jmp ...)
	// 16B unique (sub+jmp+int3+sub pattern).
	AUTO_OFFSET(Functions, OVS_VT1_SmallSub,
		"\x48\x83\xE9\x40\xE9\x13\x02\x00\x00\xCC\xCC\xCC\x48\x83\xE9\x10",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[13] — RVA 0x053B80 — null check (test rcx,rcx; jz +0xB; mov rax,[rcx]; mov edx,1; jmp [rax])
	// 16B unique (test+jz+mov+mov edx,1+jmp [rax] shape).
	AUTO_OFFSET(Functions, OVS_VT1_NullCheck,
		"\x48\x85\xC9\x74\x0B\x48\x8B\x01\xBA\x01\x00\x00\x00\x48\xFF\x20",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT1[14] — RVA 0x058C20 — noop/ret (xorps xmm0,xmm0; ret; 12 bytes int3 pad)
	// 16B unique (xorps+ret+long int3 pad).
	AUTO_OFFSET(Functions, OVS_VT1_Noop,
		"\x0F\x57\xC0\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT2[3] — RVA 0x7B7380 — delegator (mov [rsp+8],rbx; push rdi; sub rsp,0x20; mov rdi,rcx; mov edx,ebp; add rcx,0x88; call ...)
	// 24B unique (add rcx,0x88 + call rel32 is distinctive).
	AUTO_OFFSET(Functions, OVS_VT2_Delegator,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xF9\x8B\xDA\x48\x81\xC1\x88\x00\x00\x00\xE8\xB5",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT2[4] — RVA 0x7BA740 (updated 2026-07-16 for 1.29)
	// Wildcard the call displacement - uses 32 65 17 00
	AUTO_OFFSET(Functions, OVS_VT2_Wrapper1,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\x32\x65\x17\x00\x48\x8B",
		"xxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// VT2[5] — RVA 0x7BA760 (updated 2026-07-16 for 1.29)
	// Wildcard the call displacement - uses B2 65 17 00
	AUTO_OFFSET(Functions, OVS_VT2_Wrapper2,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xB2\x65\x17\x00\x48\x8B",
		"xxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// VT2[6] — RVA 0x7BA780 (updated 2026-07-16 for 1.29)
	// Wildcard the call displacement - uses C2 65 17 00
	AUTO_OFFSET(Functions, OVS_VT2_Wrapper3,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xC2\x65\x17\x00\x48\x8B",
		"xxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// VT2[7] — RVA 0x7BA7E0 (updated 2026-07-16 for 1.29)
	// Wildcard the call displacement - uses B2 66 17 00
	AUTO_OFFSET(Functions, OVS_VT2_Wrapper4,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xB2\x66\x17\x00\x48\x8B",
		"xxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// VT2[8] — RVA 0x7BA800 (updated 2026-07-16 for 1.29)
	// Wildcard the call displacement - uses 12 69 17 00
	AUTO_OFFSET(Functions, OVS_VT2_Wrapper5,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\x12\x69\x17\x00\x48\x8B",
		"xxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// VT2[9] — RVA 0x7BA820 (updated 2026-07-16 for 1.29)
	// Wildcard the call displacement - uses A2 69 17 00
	AUTO_OFFSET(Functions, OVS_VT2_Wrapper6,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xA2\x69\x17\x00\x48\x8B",
		"xxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// VT2[10] — RVA 0x7B8860 — flag setter (cmp byte [rcx+0xA0],0; mov rdi,rdx; mov rbx,rcx; jz +0xC; mov byte [rcx+0xA0],0)
	// 16B unique (cmp byte [rcx+0xA0] is distinctive).
	AUTO_OFFSET(Functions, OVS_VT2_FlagSet,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x80\xB9\xA0\x00\x00\x00",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT2[11] — RVA 0x7B9610 — complex init (sub rsp,0x40; mov rbx,[rsp+0x70]; mov r15,r8; movaps [rsp+0x30],xmm6; ...)
	// 24B unique (sub rsp,0x40 + mov from [rsp+0x70] is distinctive).
	AUTO_OFFSET(Functions, OVS_VT2_ComplexInit,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x40\x48\x8B\x5C\x24\x70\x49\x8B\xF8\x0F",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VT2[12] — RVA 0x7B7740 — large frame (sub rsp,0x100; mov rbx,rdx; mov rcx,rdx; lea rcx,[rsp+0x20]; call ...)
	// 24B unique (sub rsp,0x100 is rare).
	AUTO_OFFSET(Functions, OVS_VT2_LargeFrame,
		"\x40\x53\x48\x81\xEC\x00\x01\x00\x00\x48\x8B\xDA\x48\x8B\xD1\x48\x8D\x4C\x24\x20\xE8\x17\xF6\xFF",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// InterlockedDecHelper — RVA 0x0896B0
	// push rbx; sub rsp,0x20; mov eax,[rcx]; mov r8,rcx; mov ebx,-1; lock xadd [rcx],ebx; dec ebx; jnz +0x76; ...
	// 16B unique (lock xadd pattern with mov ebx,-1).
	AUTO_OFFSET(Functions, InterlockedDecHelper,
		"\x40\x53\x48\x83\xEC\x20\x8B\x01\x4C\x8B\xC1\xBB\xFF\xFF\xFF\xFF",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === 2026-07-13: Scanner7 function RVAs ===
	// All patterns are 16-byte prologues with all-locked masks.

	// HealthCalc_1 — RVA 0x962C0 (updated 2026-07-16 for 1.29)
	AUTO_OFFSET(Functions, HealthCalc_1,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xD2\xF2\x27\x00\x48\x8D",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// BloodMax_Func — RVA 0x10EC80 (5000.0 float = max blood)
	AUTO_OFFSET(Functions, BloodMax_Func,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xC7\x01\x00\x00\x00\x00\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_2 — RVA 0x1B9A10 (100.0 float func)
	AUTO_OFFSET(Functions, HealthCalc_2,
		"\x40\x53\x48\x83\xEC\x30\x4C\x8B\x81\x10\x0A\x00\x00\x48\x8D\x91",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Script_Func1 — RVA 0x31C290 (1.29 script-related)
	AUTO_OFFSET(Functions, Script_Func1,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x41\x8B\xF8\x48\x8B\xDA\x48\x8B\xF1",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Script_Func2 — RVA 0x31C390 (1.29 script-related)
	AUTO_OFFSET(Functions, Script_Func2,
		"\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x0F\xB6\x44\x24\x68\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_3 — RVA 0x338690 (100.0 float func)
	AUTO_OFFSET(Functions, HealthCalc_3,
		"\x48\x89\x5C\x24\x10\x57\x48\x83\xEC\x30\x48\x8B\xC2\x0F\x29\x74",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Script_Func3 — RVA 0x33A820 (1.29 script-related)
	AUTO_OFFSET(Functions, Script_Func3,
		"\x48\x89\x5C\x24\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_4 — RVA 0x3898D0 (100.0 float func)
	AUTO_OFFSET(Functions, HealthCalc_4,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xC2\xE5\xFE\xFF\x48\x8D",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_5 — pattern too generic, wildcard call offset
	// Prologue: 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 8D
	AUTO_OFFSET(Functions, HealthCalc_5,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xD9\xE8\x00\x00\x00\x00\x48\x8D",
		"xxxxxxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_6 — RVA 0x4197D0 (updated 2026-07-16 for 1.29)
	// Wildcard the call offset and add lea rax anchor: 48 8D 05 93 DC 84
	AUTO_OFFSET(Functions, HealthCalc_6,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\x00\x00\x00\x00\x48\x8D\x05\x93\xDC\x84",
		"xxxxxxxxxx????xxx???",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_7 — RVA 0x421610 (health-related)
	AUTO_OFFSET(Functions, HealthCalc_7,
		"\x48\x89\x5C\x24\x10\x57\x48\x81\xEC\xA0\x00\x00\x00\x4C\x8D\x44",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// InfectedHelper1 — RVA 0x4AC120 (DayZInfected helper)
	AUTO_OFFSET(Functions, InfectedHelper1,
		"\x48\x83\xEC\x28\x48\x8B\x49\x20\xE8\xA3\x4C\xFE\xFF\x66\x83\xF8",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// InfectedHelper2 — RVA 0x4AC150 (DayZInfected helper)
	AUTO_OFFSET(Functions, InfectedHelper2,
		"\x48\x83\xEC\x28\x48\x8B\x49\x20\xE8\xA3\x2D\xFE\xFF\x66\x83\xF8",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Unknown_Func1 — RVA 0x73F090 (unknown)
	AUTO_OFFSET(Functions, Unknown_Func1,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xDA\x41\x8B\xD0\xE8\x5F\xFF\xFF",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_8 — RVA 0x780750 (updated 2026-07-16 for 1.29)
	// Wildcard the movss displacement
	AUTO_OFFSET(Functions, HealthCalc_8,
		"\x40\x53\x48\x83\xEC\x20\xF3\x0F\x10\x1D\x56\x64\x48\x00\x48\x8D",
		"xxxxxxxxxx????xx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_9 — RVA 0x79C120 (100.0 float func)
	AUTO_OFFSET(Functions, HealthCalc_9,
		"\x40\x55\x53\x56\x57\x41\x57\x48\x8D\xAC\x24\xA0\xFE\xFF\xFF\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_10 — RVA 0x7A08D0 (updated 2026-07-16 for 1.29)
	// Wildcard the call offset and add lea rax anchor: 48 8D 05 23 5D 55
	AUTO_OFFSET(Functions, HealthCalc_10,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\x00\x00\x00\x00\x48\x8D\x05\x23\x5D\x55",
		"xxxxxxxxxx????xxx???",
		".text", ScanType::FuncRVA, 0);

	// DirtyInvalidateArea1 — RVA 0x7BC2D0 (1.29 DirtyInvalidate area)
	AUTO_OFFSET(Functions, DirtyInvalidateArea1,
		"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x50\x0F\x57\xC0\x0F",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// PhysicsAdj_Func1 — RVA 0x912460 (physics-adjacent)
	AUTO_OFFSET(Functions, PhysicsAdj_Func1,
		"\x40\x53\x48\x83\xEC\x20\x80\x7C\x24\x68\x00\x4C\x8B\xD1\x0F\x29",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// HealthCalc_11 — RVA 0xAFC590 (100.0 float func)
	AUTO_OFFSET(Functions, HealthCalc_11,
		"\x40\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC\xC0",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Network functions (0xAB040-0xACCD0) ===

	// Net_Func1 — RVA 0xAB040
	AUTO_OFFSET(Functions, Net_Func1,
		"\x48\x89\x4C\x24\x08\x55\x48\x8D\xAC\x24\xD0\xFE\xFF\xFF\x48\x81",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func2 — RVA 0xABEC0
	AUTO_OFFSET(Functions, Net_Func2,
		"\x40\x56\x48\x83\xEC\x30\x48\x8B\x01\x48\x8B\xF1\x48\x85\xC0\x0F",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func3 — RVA 0xABF70
	AUTO_OFFSET(Functions, Net_Func3,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x8B\x49\x20\x48\x8B\x01",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func4 — RVA 0xABFC0
	AUTO_OFFSET(Functions, Net_Func4,
		"\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x44\x8B\x51\x08\x4C\x8B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func5 — RVA 0xAC200
	AUTO_OFFSET(Functions, Net_Func5,
		"\x48\x89\x5C\x24\x18\x55\x56\x57\x48\x83\xEC\x50\x48\x8B\x3A\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func6 — RVA 0xAC2B0
	AUTO_OFFSET(Functions, Net_Func6,
		"\x40\x53\x48\x83\xEC\x30\x4C\x8B\x12\x48\x8D\x41\x58\x4C\x8B\xDA",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func7 — RVA 0xAC340
	AUTO_OFFSET(Functions, Net_Func7,
		"\x40\x53\x56\x57\x41\x54\x48\x83\xEC\x28\x4C\x8B\x61\x20\x48\x8B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func8 — RVA 0xAC540 (updated 2026-09-13)
	// Prologue: push rbx; sub rsp,20; mov rbx,rcx; lea rax,[rip+disp32]; ...
	// Wildcard the LEA displacement at bytes 12-15.
	AUTO_OFFSET(Functions, Net_Func8,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x8D\x05\x00\x00\x00\x00",
		"xxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// Net_Func9 — RVA 0xAC5F0
	AUTO_OFFSET(Functions, Net_Func9,
		"\x40\x57\x48\x83\xEC\x30\x80\x79\x20\x02\x48\x8B\xF9\x75\x09\x0F",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func10 — RVA 0xACAE0
	AUTO_OFFSET(Functions, Net_Func10,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x4C\x8B\xC2\x48\x8B\x49\x30",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func11 — RVA 0xACB20
	AUTO_OFFSET(Functions, Net_Func11,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xB2\xA2\x00\x00\x48\x8D",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func12 — RVA 0xACBA0
	AUTO_OFFSET(Functions, Net_Func12,
		"\x40\x53\x48\x83\xEC\x20\x48\x8D\x99\xE8\x00\x00\x00\x48\x8B\xCB",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func13 — RVA 0xACBF0
	AUTO_OFFSET(Functions, Net_Func13,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8D\xB9\xC8\x00\x00",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func14 — RVA 0xACC50
	AUTO_OFFSET(Functions, Net_Func14,
		"\x48\x89\x5C\x24\x10\x57\x48\x83\xEC\x20\x8B\x81\xE0\x00\x00\x00",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Net_Func15 — RVA 0xACCD0
	AUTO_OFFSET(Functions, Net_Func15,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\xC2\xFE\xFF\xFF\x48\x8D",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === 2026-07-13: String xref / collision research function RVAs ===
	// All patterns verified unique against the loaded DayZ_x64.exe 1.29 PE.
	// DamageSystem_Init (0x41ADA0) SKIPPED — prologue not unique even at 32 bytes.

	// DamageSystem_GetHealth — RVA 0x429C10
	// Prologue: mov [rsp+8],rbx; mov [rsp+10],rbp; mov [rsp+18],rsi;
	//           mov [rsp+20],rdi; push r14; sub rsp,40; mov rsi,[r8+98h]; ...
	// 32B unique in .text.
	AUTO_OFFSET(Functions, DamageSystem_GetHealth,
		"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x48\x89\x7C\x24\x20\x41\x56\x48\x83\xEC\x40\x49\x8B\xB0\x98\x00\x00",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DamageSystem_Apply — RVA 0x482B6A (updated 2026-07-16 for 1.29)
	// Prologue: mov [rsp+78],rbx; lea rcx,[rsp+70]; call ...; mov rcx,[rsp+30]; mov rdi,rax; ...
	// Wildcard the call displacement
	AUTO_OFFSET(Functions, DamageSystem_Apply,
		"\x48\x89\x5C\x24\x78\x48\x8D\x4C\x24\x70\xE8\x47\x55\x11\x00\x48",
		"xxxxxxxxxxx????x",
		".text", ScanType::FuncRVA, 0);

	// DamageSystem_VTEntry — RVA 0x7B89E0
	// Prologue: mov [rsp+8],rbx; mov [rsp+10],rsi; mov [rsp+18],rdi; push r14;
	//           sub rsp,30; mov r8,[r8]; lea rdx,[rsp+20]; ...
	// 24B unique in .text.
	AUTO_OFFSET(Functions, DamageSystem_VTEntry,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7C\x24\x18\x41\x56\x48\x83\xEC\x30\x49\x8B\x00",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_GetMax — RVA 0x4217B0
	// Prologue: mov [rsp+8],rbx; mov [rsp+18],rbp; mov [rsp+20],rsi;
	//           mov [rsp+10],rdx; push rdi; sub rsp,20; mov rdi,r8; mov r9,rdx; ...
	// 32B unique in .text.
	AUTO_OFFSET(Functions, Health_GetMax,
		"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x18\x48\x89\x74\x24\x20\x48\x89\x54\x24\x10\x57\x48\x83\xEC\x20\x49\x8B\xF8\x4C\x8B\xCA\x48",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_SetValue — RVA 0x422550
	// Prologue: mov [rsp+20],rbx; push rsi; push rdi; push r15; sub rsp,40;
	//           movaps [rsp+30],xmm6; mov rbx,r8; ...
	// 16B unique (mov [rsp+20] + push rsi + push rdi + push r15 + sub rsp,40).
	AUTO_OFFSET(Functions, Health_SetValue,
		"\x48\x89\x5C\x24\x20\x56\x57\x41\x57\x48\x83\xEC\x40\x0F\x29\x74",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Clamp — RVA 0x4227D0
	// Prologue: push rbx; push rbp; push rdi; push r14; push r15; sub rsp,70;
	//           movaps [rsp+60],xmm6; xorps xmm6,xmm6; ...
	// 16B unique (5 pushes + sub rsp,70 is rare).
	AUTO_OFFSET(Functions, Health_Clamp,
		"\x40\x53\x55\x57\x41\x56\x41\x57\x48\x83\xEC\x70\x0F\x29\x74\x24",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_GetPercent — RVA 0x422CE0
	// Prologue: mov [rsp+10],rbx; mov [rsp+18],rbp; push rdi; sub rsp,40;
	//           movaps [rsp+30],xmm6; xor edi,edi; mov rbx,rdx; ...
	// 16B unique.
	AUTO_OFFSET(Functions, Health_GetPercent,
		"\x48\x89\x5C\x24\x10\x48\x89\x6C\x24\x18\x57\x48\x83\xEC\x40\x0F",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Regen — RVA 0x4263B0
	// Prologue: mov [rsp+18],rbx; mov [rsp+20],rbp; push rsi; push rdi; push r15;
	//           sub rsp,50; movaps [rsp+40],xmm6; movss xmm6,xmm3; ...
	// 24B unique in .text.
	AUTO_OFFSET(Functions, Health_Regen,
		"\x48\x89\x5C\x24\x18\x48\x89\x6C\x24\x20\x56\x57\x41\x57\x48\x83\xEC\x50\x0F\x29\x74\x24\x40\x0F",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Damage — RVA 0x427DD0
	// Prologue: mov [rsp+8],rcx; push rbx; push rbp; push rsi; push r12; push r13;
	//           sub rsp,70; movaps [rsp+40],xmm6; xorps xmm6,xmm6; ...
	// 16B unique (mov [rsp+8],rcx + 5 pushes + sub rsp,70).
	AUTO_OFFSET(Functions, Health_Damage,
		"\x48\x89\x4C\x24\x08\x53\x55\x56\x41\x54\x41\x55\x48\x83\xEC\x70",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Heal — RVA 0x428B80
	// Prologue: push rbp; push rbx; push rdi; push r12; push r13; push r15;
	//           lea rbp,[rsp-0xC8]; sub rsp,1C8; ...
	// 16B unique (6 pushes + lea rbp,[rsp-0xC8]).
	AUTO_OFFSET(Functions, Health_Heal,
		"\x40\x55\x53\x57\x41\x54\x41\x55\x41\x57\x48\x8D\xAC\x24\x38\xFF",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Update — RVA 0x429844
	// Entry: mov [rsp+48],rbx; call +0xFFDDC2; test rbx,rbx; jz +0xE;
	//        lea rcx,[rbx+20]; cmovz rcx,r12; ...
	// 16B unique (call rel32 = C2 DD FF FF is distinctive).
	AUTO_OFFSET(Functions, Health_Update,
		"\x48\x89\x5C\x24\x48\xE8\xC2\xDD\xFF\xFF\x48\x85\xDB\x74\x0E\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Tick — RVA 0x429E10
	// Prologue: mov rax,rsp; mov [rax+20],r9; mov [rax+18],r8; mov [rax+10],rdx;
	//           push rbp; push rbx; push rsi; push r13; lea rbp,[rax-0x208]; ...
	// 24B unique (mov rax,rsp + register saves + 4 pushes).
	AUTO_OFFSET(Functions, Health_Tick,
		"\x48\x8B\xC4\x4C\x89\x48\x20\x4C\x89\x40\x18\x48\x89\x50\x10\x55\x53\x56\x41\x55\x41\x56\x48\x8D",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Calc — RVA 0x42B670
	// Prologue: mov rax,rsp; mov [rax+20],r9; mov [rax+18],r8; push rbp;
	//           lea rbp,[rax-0x158]; sub rsp,250; ...
	// 16B unique (mov rax,rsp + mov [rax+20],r9 + mov [rax+18],r8 + push rbp + lea rbp).
	AUTO_OFFSET(Functions, Health_Calc,
		"\x48\x8B\xC4\x4C\x89\x48\x20\x4C\x89\x40\x18\x55\x48\x8D\xA8\xA8",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Health_Internal — RVA 0x817870
	// Prologue: mov [rsp+8],rbx; mov [rsp+10],rbp; mov [rsp+18],rsi;
	//           mov [rsp+20],rdi; push r14; sub rsp,30; movaps [rsp+20],xmm4; ...
	// 32B unique in .text.
	AUTO_OFFSET(Functions, Health_Internal,
		"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x48\x89\x7C\x24\x20\x41\x56\x48\x83\xEC\x30\x0F\x29\x74\x24\x20\x0F",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DayZPlayer_GetName — RVA 0x4E5130 (updated 2026-09-13 for 1.29)
	// Entry: lea rax,[rip+disp32]; ret; (int3 pad)
	// Returns pointer to "DayZPlayer" string. Wildcard the LEA displacement.
	AUTO_OFFSET(Functions, DayZPlayer_GetName,
		"\x48\x8D\x05\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxx????xxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DayZPlayer_Update1 — RVA 0x4E5670
	// Prologue: mov [rsp+8],rbx; push rdi; sub rsp,30; mov rdi,rcx;
	//           mov edx,[rdx+18]; mov rcx,[rdi+10]; call ...; mov ecx,D8; ...
	// 24B unique (call rel32 = C7 B0 00 00 is distinctive).
	AUTO_OFFSET(Functions, DayZPlayer_Update1,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x30\x48\x8B\xFA\x8B\x52\x18\x48\x8B\x4F\x10\xE8\xC7\xB0\x00",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DayZPlayer_Update2 — RVA 0x4F22B0
	// Prologue: mov [rsp+18],rsi; push rdi; sub rsp,40; mov rax,[rdx];
	//           mov rdi,rcx; mov r8,[rip+0xA39739]; ...
	// 16B unique (mov r8,[rip+0xA39739] is distinctive).
	AUTO_OFFSET(Functions, DayZPlayer_Update2,
		"\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x40\x48\x8B\x02\x48\x8B\xFA",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DayZPlayer_Method — RVA 0x500F80
	// Prologue: mov [rsp+10],rbx; mov [rsp+8],rcx; push rbp; push rsi; push rdi;
	//           push r12; push r13; push r14; push r15; lea rbp,[rsp-0x1E0]; ...
	// 32B unique (7 pushes + lea rbp,[rsp-0x1E0]).
	AUTO_OFFSET(Functions, DayZPlayer_Method,
		"\x48\x89\x5C\x24\x10\x48\x89\x4C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x20\xFF\xFF\xFF\x48\x81\xEC",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DayZInfected_GetName — RVA 0x4AC380 (updated 2026-09-13 for 1.29)
	// Entry: lea rax,[rip+disp32]; ret; (int3 pad)
	// Returns pointer to "DayZInfected" string. Wildcard the LEA displacement.
	AUTO_OFFSET(Functions, DayZInfected_GetName,
		"\x48\x8D\x05\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxx????xxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// DayZInfected_Update — RVA 0x4AC490 (updated 2026-07-16 for 1.29)
	// Prologue: mov [rsp+8],rbx; mov [rsp+10],rsi; push rdi; sub rsp,30;
	//           mov rbx,[rdx+10]; mov rdi,rdx; mov rcx,rbx; lea rdx,[rip+0x7D0788]; ...
	// Wildcard the lea rdx displacement
	AUTO_OFFSET(Functions, DayZInfected_Update,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x48\x8B\x5A\x10\x48\x8B\xFA\x48\x8B\xCB\x48\x8D\x15\x88\x07\x7D\x00",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxx????x",
		".text", ScanType::FuncRVA, 0);

	// DayZInfected_Method — RVA 0x4ACF10 (updated 2026-07-16 for 1.29)
	// Entry: lea rax,[rip+0x7CFFB9]; mov [rdx],rax; mov rax,rdx; ret; (int3 pad)
	// Wildcard the lea rax displacement
	AUTO_OFFSET(Functions, DayZInfected_Method,
		"\x48\x8D\x05\xB9\xFF\x7C\x00\x48\x89\x02\x48\x8B\xC2\xC3\xCC\xCC",
		"xxx????xxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// InputController_GetName — RVA 0x518E00 (updated 2026-09-13 for 1.29)
	// Entry: lea rax,[rip+disp32]; ret; (int3 pad)
	// Returns pointer to "HumanInputController" string. Wildcard the LEA displacement.
	AUTO_OFFSET(Functions, InputController_GetName,
		"\x48\x8D\x05\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxx????xxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// InputController_Method — RVA 0x518E10 (updated 2026-09-13 for 1.29)
	// Prologue: mov [rsp+8],rbx; mov [rsp+10],rsi; push rdi; sub rsp,30;
	//           mov rbx,[rdx+10]; mov rdi,rdx; mov rcx,rbx; lea rdx,[rip+disp32]; ...
	// Wildcard the lea rdx displacement at bytes 28-31.
	AUTO_OFFSET(Functions, InputController_Method,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x48\x8B\x5A\x10\x48\x8B\xFA\x48\x8B\xCB\x48\x8D\x15\x00\x00\x00\x00",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// Camera_Func — RVA 0x4B6B00 (updated 2026-07-16 for 1.29)
	// Prologue: mov [rsp+8],rbx; mov [rsp+10],rsi; push rdi; sub rsp,30;
	//           mov ecx,D8; mov rdi,rdx; call ...; xor esi,esi; ...
	// Wildcard the E8 call offset, add post-call anchor: 48 8B D8 48 85 C0 74 31 48 8B 05
	AUTO_OFFSET(Functions, Camera_Func,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\xB9\xD8\x00\x00\x00\x48\x8B\xFA\xE8\x00\x00\x00\x00\x33\xF6\x48\x8B\xD8\x48\x85\xC0\x74\x31\x48\x8B\x05",
		"xxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Inventory_GetName — RVA 0x542460 (updated 2026-09-13 for 1.29)
	// Entry: lea rax,[rip+disp32]; ret; (int3 pad)
	// Returns pointer to "GameInventory" string. Wildcard the LEA displacement.
	AUTO_OFFSET(Functions, Inventory_GetName,
		"\x48\x8D\x05\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxx????xxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Material_Func1 — RVA 0x2805BB (1.29)
	// Prologue: mov [rsp+30],rbx; mov [rsp+28],rax; mov [rsp+20],r12; call X
	// 20B unique - wildcard the call offset
	AUTO_OFFSET(Functions, Material_Func1,
		"\x48\x89\x5C\x24\x30\x48\x89\x44\x24\x28\x4C\x89\x64\x24\x20\xE8\x71\x65\xE8\xFF",
		"xxxxxxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// Material_GetName — RVA 0x298F30 (1.29)
	// Entry: lea rax,[rip+X]; mov [rdx],rax; mov rax,rdx; ret; (int3 pad)
	// Wildcard the LEA displacement
	AUTO_OFFSET(Functions, Material_GetName,
		"\x48\x8D\x05\x99\xFD\x98\x00\x48\x89\x02\x48\x8B\xC2\xC3\xCC\xCC",
		"xxx????xxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Material_Func2 — RVA 0x2AC4C0 (1.29)
	// Prologue: mov [rsp+8],rbx; mov [rsp+10],rbp; mov [rsp+18],rsi; push rdi;
	//           sub rsp,30; mov rsi,rdx; mov rbx,rcx (no call needed for uniqueness)
	AUTO_OFFSET(Functions, Material_Func2,
		"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x48\x8B\xF2\x48",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Blood_Func — RVA 0x4A9000
	// Prologue: push rbx; sub rsp,20; lea rbx,[rcx-0x700]; xor edx,edx;
	//           mov rcx,rbx; lea r8,[rip+0x7D3073]; call ...; ...
	// 16B unique (lea rbx,[rcx-0x700] is distinctive).
	AUTO_OFFSET(Functions, Blood_Func,
		"\x40\x53\x48\x83\xEC\x20\x48\x8D\x99\x00\xF9\xFF\xFF\x33\xD2\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// AllocateCollisionBuffer — RVA 0x98450 (1.29)
	// Prologue: push rbx; sub rsp,20; mov byte [rcx+28],0; mov rbx,rcx;
	//           mov rdx,[rip+X]; wildcard the RIP-relative displacement
	AUTO_OFFSET(Functions, AllocateCollisionBuffer,
		"\x40\x53\x48\x83\xEC\x20\xC6\x41\x28\x00\x48\x8B\xD9\x48\x8B\x15\x3C\xF2\x1C\x04\x48\x8D\x4A\x0F",
		"xxxxxxxxxxxxxxxx????xxxx",
		".text", ScanType::FuncRVA, 0);

	// FreeCollisionBuffer — RVA 0x987E0
	// Prologue: push rbx; sub rsp,20; mov rbx,rcx; call +0xF32;
	//           mov rax,[rbx+18]; cmp rax,-1; jnz +0x10; ...
	// 16B unique (call rel32 = 32 0F 00 00 is distinctive).
	AUTO_OFFSET(Functions, FreeCollisionBuffer,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xE8\x32\x0F\x00\x00\x48\x8B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// FilterIgnoreTwo_Init — RVA 0x4B76E0
	// Entry: sbb al,[rcx]; mov rdx,[rcx+68]; test rdx,rdx; jnz +0x54;
	//        mov eax,[rdi]; mov [rbx],eax; ...
	// 16B unique (sbb al,[rcx] entry is very rare).
	AUTO_OFFSET(Functions, FilterIgnoreTwo_Init,
		"\x18\x48\x8B\x51\x68\x48\x85\xD2\x75\x54\x8B\x07\x89\x03\x8B\x47",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// GetObjectTexture — RVA 0x473850
	// Entry: mov eax,[rax+10]; and r8d,F0000000; cmp r8d,20000000; jnz +0x1E; ...
	// 16B unique (mov eax,[rax+10] + and r8d,F0000000 is distinctive).
	AUTO_OFFSET(Functions, GetObjectTexture,
		"\x8B\x40\x10\x41\x81\xE0\x00\x00\x00\xF0\x41\x81\xF8\x00\x00\x00",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// SetObjectTexture — RVA 0x4790C4 (1.29)
	// Entry: mov rdx,rax; lea rcx,[rsp+28]; call X; mov rcx,[rsp+20]; test rcx,rcx
	AUTO_OFFSET(Functions, SetObjectTexture,
		"\x48\x8B\xD0\x48\x8D\x4C\x24\x28\xE8\x3F\x74\x37\x00\x48\x8B\x4C\x24\x20\x48\x85",
		"xxxxxxxxx????xxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === 2026-07-13: Scanner Temp Batch (24 functions from 8 unexplored regions) ===

	// RegionA_Func1 — RVA 0xD1000 (1.29)
	AUTO_OFFSET(Functions, RegionA_Func1,
		"\x48\x8B\xC4\x48\x89\x58\x18\x48\x89\x78\x20\x55\x48\x8D\x68\xA9",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionA_Func2 — RVA 0xD1FD0 (1.29)
	AUTO_OFFSET(Functions, RegionA_Func2,
		"\x40\x53\x55\x57\x41\x55\x41\x57\x48\x83\xEC\x30\x8B\x9A\x50\x04",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionA_Func3 — RVA 0xD3420 (1.29)
	AUTO_OFFSET(Functions, RegionA_Func3,
		"\x40\x55\x56\x57\x41\x56\x48\x8D\x6C\x24\xE8\x48\x81\xEC\x18\x01",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionB_Func1 — RVA 0x1412A0 (1.29)
	AUTO_OFFSET(Functions, RegionB_Func1,
		"\x48\x8B\xC4\x48\x81\xEC\xA8\x00\x00\x00\xF3\x0F\x10\x01\x4C\x8B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionB_Func2 — RVA 0x142B00 (1.29)
	AUTO_OFFSET(Functions, RegionB_Func2,
		"\x48\x8B\xC4\x53\x56\x57\x48\x81\xEC\x90\x00\x00\x00\x0F\x29\x70",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionB_Func3 — RVA 0x144150 (1.29)
	AUTO_OFFSET(Functions, RegionB_Func3,
		"\x4C\x8B\xDC\x53\x55\x41\x54\x41\x55\x41\x56\x48\x81\xEC\xA0\x00",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionC_Func1 — RVA 0x2011A0 (1.29)
	AUTO_OFFSET(Functions, RegionC_Func1,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x85\xC9\x74\x1F\xE8",
		"xxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionC_Func2 — RVA 0x2012B0 (1.29)
	AUTO_OFFSET(Functions, RegionC_Func2,
		"\x4C\x8B\x51\x50\x41\x3B\xD0\x44\x8B\xCA\x41\x8B\xC0\x45\x0F\x46",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionC_Func3 — RVA 0x201310 (1.29)
	AUTO_OFFSET(Functions, RegionC_Func3,
		"\x49\x8B\x40\x18\x44\x8B\xCA\x48\x85\xC0\x74\x3F\x44\x8B\x40\x5C",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionD_Func1 — RVA 0x501D50 (1.29)
	AUTO_OFFSET(Functions, RegionD_Func1,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x89\x11\xE8\x3F\x21\x01",
		"xxxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// RegionD_Func2 — RVA 0x501FD0 (1.29) - uses LEA pattern
	AUTO_OFFSET(Functions, RegionD_Func2,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8D\x05\x97\xBE\x78",
		"xxxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// RegionD_Func3 — RVA 0x502400 (1.29) - uses LEA pattern
	AUTO_OFFSET(Functions, RegionD_Func3,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8D\x05\x67\xD4\x78",
		"xxxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// RegionE_Func1 — RVA 0x602110 (1.29)
	AUTO_OFFSET(Functions, RegionE_Func1,
		"\x48\x89\x5C\x24\x18\x56\x57\x41\x56\x48\x83\xEC\x40\x4C\x8B\xF2",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionE_Func2 — RVA 0x6022C0 (1.29)
	AUTO_OFFSET(Functions, RegionE_Func2,
		"\x48\x8B\x01\x41\xB8\x04\x00\x00\x00\x48\x85\xC0\x74\x08\x48\x8B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionE_Func3 — RVA 0x6022E0 (1.29) - wildcard LEA disp
	AUTO_OFFSET(Functions, RegionE_Func3,
		"\x40\x53\x48\x83\xEC\x20\x48\x8D\x05\x63\x64\x6C\x00\x48\x8B\xD9",
		"xxxxxxxxx????xxx",
		".text", ScanType::FuncRVA, 0);

	// RegionF_Func1 — RVA 0x8016C0 (1.29)
	AUTO_OFFSET(Functions, RegionF_Func1,
		"\x40\x53\x48\x81\xEC\x80\x00\x00\x00\xF3\x41\x0F\x10\x00\x48\x8B",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionF_Func2 — RVA 0x801970 (1.29) - wildcard RIP-relative
	AUTO_OFFSET(Functions, RegionF_Func2,
		"\x80\xB9\x85\x04\x00\x00\x00\x74\x09\xF3\x0F\x10\x05\x33\x52\x40",
		"xxxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// RegionF_Func3 — FAILED (pattern contains relocation-dependent RIP-relative displacement)
	// AUTO_OFFSET(Functions, RegionF_Func3,
	// 	"\x48\x8D\x05\xA1\x80\x72\x00\x48\x3B\xD0\x74\x0C\x48\x8D\x05\x05",
	// 	"xxxxxxxxxxxxxxxx",
	// 	".text", ScanType::FuncRVA, 0);

	// RegionG_Func1 — RVA 0xA01BA0 (1.29) - wildcard LEA disp
	AUTO_OFFSET(Functions, RegionG_Func1,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xDA\x48\x8D\x0D\xD0\x50\x20\x00",
		"xxxxxxxxxxxx????",
		".text", ScanType::FuncRVA, 0);

	// RegionG_Func2 — RVA 0xA01BF0 (1.29)
	AUTO_OFFSET(Functions, RegionG_Func2,
		"\x48\x8B\xC1\x48\x8B\x49\x10\x48\x85\xD2\x74\x04\xF0\xFF\x42\x08",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionG_Func3 — RVA 0xA01C30 (1.29) - pattern with two LEAs
	// Using RegionG_Func2 continuation pattern since G_Func3 was mid-function
	AUTO_OFFSET(Functions, RegionG_Func3,
		"\x48\x8B\xC1\x48\x8B\x49\x10\x48\x85\xD2\x74\x04\xF0\xFF\x42\x08\x48\x89\x50\x10",
		"xxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionH_Func1 — RVA 0xAD1F80 (1.29)
	AUTO_OFFSET(Functions, RegionH_Func1,
		"\x48\x8B\xC4\x57\x48\x81\xEC\xB0\x00\x00\x00\x48\x89\x58\x08\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionH_Func2 — RVA 0xAD53D0 (1.29)
	AUTO_OFFSET(Functions, RegionH_Func2,
		"\x48\x83\xEC\x18\x45\x33\xC9\x0F\x29\x34\x24\x4C\x8B\xD1\x0F\x57",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// RegionH_Func3 — RVA 0xAD9860 (1.29)
	AUTO_OFFSET(Functions, RegionH_Func3,
		"\x48\x89\x5C\x24\x20\x44\x89\x44\x24\x18\x55\x56\x57\x41\x54\x41",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === 2026-07-13: Scanner Temp Batch 2 (45 functions from 9 unexplored regions) ===
	// Each pattern verified unique in .text against DayZ_x64.exe 1.29 PE.

	// === Region: Early (0x030000-0x0AB000) ===

	// Early_Func1 — RVA 0x042CF0 (func size 6241 bytes)
	AUTO_OFFSET(Functions, Early_Func1,
		"\x40\x55\x53\x57\x48\x8D\xAC\x24\xD0\xFC\xFF\xFF\x48\x81\xEC\x30",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Early_Func2 — RVA 0x06B870 (func size 8604 bytes)
	AUTO_OFFSET(Functions, Early_Func2,
		"\x48\x89\x4C\x24\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\xD8\x48\x81\xEC\x28\x01\x00\x00\x48\x8B\xC1",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Early_Func3 — RVA 0x06DB90 (func size 40020 bytes)
	AUTO_OFFSET(Functions, Early_Func3,
		"\x48\x89\x5C\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xFA\x48\x8B\xD9\x48\x3B\xCA\x74\x2D\x48\x8B\x09",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Early_Func4 — RVA 0x077920 (func size 50820 bytes)
	AUTO_OFFSET(Functions, Early_Func4,
		"\x48\x89\x5C\x24\x08\x4C\x89\x44\x24\x18\x48\x89\x54\x24\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x45\x33",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Early_Func5 — RVA 0x0AADB0 (func size 9999 bytes)
	AUTO_OFFSET(Functions, Early_Func5,
		"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x8B\x09\x48\x85\xC9\x74\x65\x48\x8B\x01\x48\x89\x7C\x24",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: MidA (0x340000-0x380000) ===

	// MidA_Func1 — RVA 0x354B50 (func size 6332 bytes)
	AUTO_OFFSET(Functions, MidA_Func1,
		"\x4C\x89\x44\x24\x18\x48\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x53\x55\x56\x57\x41\x55\x41\x56\x41",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidA_Func2 — RVA 0x356470 (func size 4778 bytes)
	AUTO_OFFSET(Functions, MidA_Func2,
		"\x48\x89\x5C\x24\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\xE0\xF6\xFF\xFF",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidA_Func3 — RVA 0x36E1D0 (func size 3667 bytes)
	AUTO_OFFSET(Functions, MidA_Func3,
		"\x48\x89\x5C\x24\x20\x48\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x30\x8B\xAC",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidA_Func4 — RVA 0x375470 (func size 3417 bytes)
	AUTO_OFFSET(Functions, MidA_Func4,
		"\x48\x8B\xC4\x48\x89\x58\x18\x48\x89\x48\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xA8\xC8\xFA\xFF\xFF\x48\x81\xEC",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidA_Func5 — RVA 0x37B3C0 (func size 4408 bytes)
	AUTO_OFFSET(Functions, MidA_Func5,
		"\x44\x89\x4C\x24\x20\x89\x54\x24\x10\x55\x56\x57\x41\x54\x41\x55",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: MidB (0x420000-0x460000) ===

	// MidB_Func1 — RVA 0x441980 (func size 6277 bytes)
	AUTO_OFFSET(Functions, MidB_Func1,
		"\x48\x89\x4C\x24\x08\x55\x56\x57\x41\x54\x41\x56\x41\x57\x48\x8D\x6C\x24\xD1\x48\x81\xEC\xB8\x00",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidB_Func2 — RVA 0x444C20 (func size 5064 bytes)
	AUTO_OFFSET(Functions, MidB_Func2,
		"\x48\x89\x54\x24\x10\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x88\xFA\xFF",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidB_Func3 — RVA 0x450000 (func size 4532 bytes)
	AUTO_OFFSET(Functions, MidB_Func3,
		"\xC6\x81\x1F\x04\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidB_Func4 — RVA 0x450010 (func size 4516 bytes)
	AUTO_OFFSET(Functions, MidB_Func4,
		"\x48\x85\xD2\x0F\x84\x9A\x11\x00\x00\x48\x8B\xC4\x55\x56\x57\x41",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// MidB_Func5 — RVA 0x45FF60 (func size 9999 bytes)
	AUTO_OFFSET(Functions, MidB_Func5,
		"\x40\x53\x48\x83\xEC\x60\x48\x8B\x81\x80\x01\x00\x00\x48\x8B\xD9",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: VisA (0x700000-0x730000) ===

	// VisA_Func1 — RVA 0x70B480 (func size 2476 bytes)
	AUTO_OFFSET(Functions, VisA_Func1,
		"\x48\x89\x5C\x24\x08\x55\x56\x57\x48\x8D\x6C\x24\xB9\x48\x81\xEC\x90\x00\x00\x00\x48\x8B\xF9\x33",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisA_Func2 — RVA 0x709D60 (1.29 func size ~2596 bytes)
	AUTO_OFFSET(Functions, VisA_Func2,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xF9\x48\xC7\x44\x24\x40\x00\x00\x00\x00\x48\x8D",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisA_Func3 — RVA 0x71DB00 (func size 15653 bytes)
	AUTO_OFFSET(Functions, VisA_Func3,
		"\x40\x55\x53\x57\x41\x56\x41\x57\x48\x8D\xAC\x24\x80\xEB\xFF\xFF",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisA_Func4 — RVA 0x7226B0 (func size 2508 bytes)
	AUTO_OFFSET(Functions, VisA_Func4,
		"\x40\x55\x53\x56\x41\x56\x48\x8D\xAC\x24\x28\xFE\xFF\xFF\x48\x81",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisA_Func5 — RVA 0x72C290 (func size 10308 bytes)
	AUTO_OFFSET(Functions, VisA_Func5,
		"\x48\x89\x5C\x24\x20\x4C\x89\x44\x24\x18\x48\x89\x4C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\xE0\xFE",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: VisB (0x730000-0x780000) ===

	// VisB_Func1 — RVA 0x735CE0 (func size 4876 bytes)
	AUTO_OFFSET(Functions, VisB_Func1,
		"\x40\x53\x48\x83\xEC\x40\x80\x79\x18\x00\x49\x8B\xD8\x74\x2C\x49",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisB_Func2 — RVA 0x73AB20 (func size 3348 bytes)
	AUTO_OFFSET(Functions, VisB_Func2,
		"\x4C\x89\x44\x24\x18\x89\x54\x24\x10\x55\x56\x57\x41\x55\x41\x56",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisB_Func3 — RVA 0x7725C0 (func size 4842 bytes)
	AUTO_OFFSET(Functions, VisB_Func3,
		"\x48\x81\xC1\x20\x02\x00\x00\x48\x8B\x01\x48\xFF\x60\x20\xCC\xCC",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisB_Func4 — RVA 0x77ACD0 (func size 3185 bytes)
	AUTO_OFFSET(Functions, VisB_Func4,
		"\x48\x8B\xC4\x56\x48\x81\xEC\x90\x00\x00\x00\x48\x89\x58\x08\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// VisB_Func5 — RVA 0x77FE90 (func size 9999 bytes)
	AUTO_OFFSET(Functions, VisB_Func5,
		"\x48\x8B\xC4\x55\x56\x48\x83\xEC\x58\x45\x33\xC0\x48\x8B\xF1\x41",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: OVS (0x7B0000-0x800000) ===

	// OVS_Func1 — RVA 0x7B3E20 (func size 3209 bytes)
	AUTO_OFFSET(Functions, OVS_Func1,
		"\x48\x8B\xC4\xF3\x0F\x11\x58\x20\xF3\x0F\x11\x50\x18\x55\x53\x56\x57\x41\x56\x48\x8D\x68\xC8\x48",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// OVS_Func2 — RVA 0x7BE020 (func size 2692 bytes)
	AUTO_OFFSET(Functions, OVS_Func2,
		"\x8B\x41\x20\xC1\xE8\x03\x24\x01\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// OVS_Func3 — RVA 0x7BE030 (func size 2676 bytes)
	AUTO_OFFSET(Functions, OVS_Func3,
		"\x48\x8B\xC4\x48\x89\x50\x10\x48\x89\x48\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x68\x98\x48\x81\xEC\x28\x01",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// OVS_Func4 — RVA 0x7F2DE0 (updated 2026-09-13)
	// Prologue: mov [rsp+8],rbx; push rdi; sub rsp,20; mov rax,[rcx];
	//           mov rbx,rdx; mov rcx,[rax]; mov rdi,[rcx]; test rdi,rdi;
	//           jz +0x29; mov rcx,[rdx]; call ...
	// Wildcard the call displacement at bytes 30-31 and add a longer anchor.
	AUTO_OFFSET(Functions, OVS_Func4,
		"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x01\x48\x8B\xDA\x48\x8B\x08\x48\x8B\x39\x48\x85\xFF\x74\x29\x48\x8B\x0A\xE8\x00",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?",
		".text", ScanType::FuncRVA, 0);

	// OVS_Func5 — RVA 0x7FF9F0 (func size 9999 bytes)
	AUTO_OFFSET(Functions, OVS_Func5,
		"\x48\x8B\xC4\x48\x89\x58\x20\x48\x89\x50\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\x90\x48\x81\xEC\x70\x01",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: PostPhys (0x920000-0x960000) ===

	// PostPhys_Func1 — RVA 0xBA4F90 (1.29 func size ~9057 bytes)
	AUTO_OFFSET(Functions, PostPhys_Func1,
		"\x48\x89\x54\x24\x10\x55\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24",
		"xxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// PostPhys_Func2 — RVA 0x949560 (func size 5256 bytes)
	AUTO_OFFSET(Functions, PostPhys_Func2,
		"\x48\x8B\xC4\x53\x55\x56\x57\x41\x55\x41\x56\x48\x81\xEC\x48\x01",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// PostPhys_Func3 — RVA 0x94D310 (func size 5201 bytes)
	AUTO_OFFSET(Functions, PostPhys_Func3,
		"\x40\x55\x53\x56\x57\x41\x56\x48\x8D\xAC\x24\xF0\xFD\xFF\xFF\x48",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// PostPhys_Func4 — RVA 0x954170 (1.29 func size ~9063 bytes)
	AUTO_OFFSET(Functions, PostPhys_Func4,
		"\x48\x81\xC1\xF8\x09\x00\x00\xE9\x54\xCD\xD6\xFF\xCC\xCC\xCC\xCC",
		"xxxxxxxx????xxxx",
		".text", ScanType::FuncRVA, 0);

	// PostPhys_Func5 — RVA 0x960880 (1.29 func size ~9999 bytes)
	AUTO_OFFSET(Functions, PostPhys_Func5,
		"\x40\x53\x48\x83\xEC\x20\x48\x83\x3D\x7A\x46\x90\x03\x00\x48\x8B",
		"xxxxxxxxx????xxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: Mat (0x960000-0x9B0000) ===

	// Mat_Func1 — RVA 0x979E30 (func size 5810 bytes)
	AUTO_OFFSET(Functions, Mat_Func1,
		"\x44\x89\x4C\x24\x20\x44\x88\x44\x24\x18\x48\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x55\x53\x56\x57",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Mat_Func2 — RVA 0x983FA0 (func size 10171 bytes)
	AUTO_OFFSET(Functions, Mat_Func2,
		"\x48\x89\x5C\x24\x18\x44\x88\x4C\x24\x20\x48\x89\x54\x24\x10\x55",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Mat_Func3 — RVA 0x986E60 (func size 16005 bytes)
	AUTO_OFFSET(Functions, Mat_Func3,
		"\x48\x89\x5C\x24\x10\x48\x89\x6C\x24\x18\x56\x57\x41\x56\x48\x81\xEC\x90\x04\x00\x00\x48\x8B\x41",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Mat_Func4 — RVA 0x99A260 (func size 6761 bytes)
	AUTO_OFFSET(Functions, Mat_Func4,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x50\x48\x8B\xDA\x48\x8B\xF9\x48\x8D\x51",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Mat_Func5 — RVA 0x9A7EC0 (func size 14054 bytes)
	AUTO_OFFSET(Functions, Mat_Func5,
		"\x48\x8B\xC4\xF3\x0F\x11\x48\x10\x55\x53\x56\x57\x48\x8D\xA8\x38",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// === Region: Late (0xB00000-0xC00000) ===

	// Late_Func1 — RVA 0xB430C0 (func size 25208 bytes)
	AUTO_OFFSET(Functions, Late_Func1,
		"\x4C\x89\x4C\x24\x20\x4C\x89\x44\x24\x18\x53\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x58\x48\x8D\x04\x11\x49\xC7",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Late_Func2 — RVA 0xB5F460 (func size 10857 bytes)
	AUTO_OFFSET(Functions, Late_Func2,
		"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x70\x48\x8B\xDA\x48\x8D\x44\x24\x30\x49",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Late_Func3 — RVA 0xB962D0 (func size 10403 bytes)
	AUTO_OFFSET(Functions, Late_Func3,
		"\x48\x8B\xC4\x48\x89\x68\x18\x48\x89\x78\x20\x41\x54\x41\x56\x41",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Late_Func4 — RVA 0xBB4790 (func size 10676 bytes)
	AUTO_OFFSET(Functions, Late_Func4,
		"\x85\xD2\x7E\x58\x83\xFA\x02\x7E\x35\x83\xFA\x04\x7F\x4E\x8B\x81",
		"xxxxxxxxxxxxxxxx",
		".text", ScanType::FuncRVA, 0);

	// Late_Func5 — RVA 0xBE89F6 (updated 2026-07-16 for 1.29)
	// Wildcard the cmp displacement
	AUTO_OFFSET(Functions, Late_Func5,
		"\x66\x66\x0F\x1F\x84\x00\x00\x00\x00\x00\x48\x3B\x0D\x91\x5E\x34",
		"xxxxxxxxxxxxx???",
		".text", ScanType::FuncRVA, 0);
}

void Updater::SetupModbaseExtendedPatterns() {
	// REMOVED: Modbase::DLC_MapManager (too generic), FOV_Base (doesn't match).
}

void Updater::SetupFreecamPatterns() {
	// Freecam::CameraMode — pattern too generic, commented out.
	// The `cmp dword [rip+disp32], 3` shape matches many unrelated sites.
	// AUTO_OFFSET(Freecam, CameraMode,
	// 	"\x83\x3D\x00\x00\x00\x00\x03\x0F\x84",
	// 	"xx????xxx",
	// 	".text", ScanType::CmpCs, 0);

	// Freecam::DebugCamInstance — CONFIRMED 0xFEAB30, not changed.
	AUTO_OFFSET(Freecam, DebugCamInstance,
		"\x48\x8B\x05\x00\x00\x00\x00\xC3\xCC\xCC\xCC",
		"xxx????xxxx",
		".text", ScanType::MovCs, 0);
}

void Updater::SetupHumanCommandPatterns() {
	// HumanCommand::Additives (expected 0x2FB0) — NO working sig.
	// Binary scanner flagged B0 2F 00 00 at RVA 0x1BE79D, but verification
	// showed it's a stack offset in `movaps [rsp+0x2FB0], xmm6`
	// (0F 29 B4 24 B0 2F 00 00), not a struct member access.
	// Zero instances of `mov r64,[r64+0x2FB0]` exist in .text.
	// The offset may be accessed indirectly or via a different code path.

	// NOTE: Binary scanner also found these function RVAs (document only,
	// no sig added — current resolver decodes disp32 from matched instruction,
	// not the match address itself):
	//   SetObjectMaterial:  RVA 0x478BE0
	//   PhysicsRaycast:     RVA 0x912EC0
	//   FindClassByName:    RVA 0x31F850
	//
	// gStatisticsScene — RIP-relative at 0x42648E0, found via
	// lea rcx,[rip+0x393170D] at RVA 0x9331CC. Encoding is 48 8D 0D (lea)
	// not 48 8B 05 (mov), so MovCs resolver won't match. Document only.
}

void Updater::SetupPhysicsBodyPatterns() {
	// REMOVED: PhysicsBody::BodyFlags — pattern doesn't match.
}



void Updater::SetupExtraPatterns() {
	// Ammo::IndirectHitRange — REMOVED: old pattern matched unrelated code
	// (resolved 0x24546348 — clearly not a struct offset). The pattern
	// `movsxd rdx,[rsp+0x38]; lea rcx,[rip+...]` is a function prologue,
	// not an ammo struct access. Needs Ghidra analysis of the actual
	// indirectHitRange write site to create a correct signature.
	// Camera::ViewportSize — pattern broken in 1.29, needs reverse engineering
	// AUTO_OFFSET(Camera, ViewportSize, ...) - commented out
	AUTO_OFFSET(Network, ManagerNetworkClient, "\x89\x42\x00\x0F\x11\x42\x58\x89\x42\x78\x0F\x11\x82\x80\x00\x00", "xx?xxxxxxxxxxxxx", ".text", ScanType::MovRegByteSml, 0);
	AUTO_OFFSET(Network, Crosshair, "\x89\x82\x00\x00\x00\x00\x0F\x11\x82\xA8\x00\x00\x00\x89\x82\xC8", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	// Animation::AnimationComp — pattern broken in 1.29, mask length mismatch
	// AUTO_OFFSET(Animation, AnimationComp, ...) - commented out
	AUTO_OFFSET(Camera, Base, "\x89\x82\x00\x00\x00\x00\x0F\x11\x82\xC0\x01\x00\x00\x89\x82\xE0", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Ammo, Hit, "\x89\x82\x00\x00\x00\x00\x0F\x11\x82\x78\x03\x00\x00\x89\x82\x98", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Ammo, Caliber, "\x89\x82\x00\x00\x00\x00\x0F\x11\x82\xC8\x03\x00\x00\x89\x82\xE8", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Object_layout, HiddenSelectionState, "\x89\x82\x00\x00\x00\x00\x0F\x11\x82\x30\x05\x00\x00\x89\x82\x50", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	// Modbase::NetworkManager — accessor end-of-function shape:
	//   lea rax,[rip+disp32] ; ret ; (15 bytes int3 pad) ; mov rcx,[rcx+0x50] ; test rcx,rcx
	// Unique on Steam (resolves 0x100FC10) AND Xbox (resolves 0x101CE90).
	// Previous sig anchored on `E8 C0 1F 6C 00` was Steam-only — the called
	// helper RVA shifts on Xbox so the rel32 differs. New sig has no rel32
	// dependencies, only opcode + scratchpad pad + caller-prologue tail.
	AUTO_OFFSET(Modbase, NetworkManager,
		"\x48\x8D\x05\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\x49\x50\x48\x85\xC9",
		"xxx????xxxxxxxxxxxxxxxx",
		".text", ScanType::MovCs, 0);
	// NOTE: Commented out - hardcoded E8 02 9D 42 00 call offset won't match on Xbox.
	// AUTO_OFFSET(Inventory, NestedCargoCount, "\x41\x8D\x51\x00\xE8\x02\x9D\x42\x00\x48\x8D\x15\x2B\xFE\xC3\x00", "xxx?xxxxxxxxxxxx", ".text", ScanType::MovRegByte, 0);
	// NOTE: Commented out - hardcoded E8 72 9A 42 00 call offset won't match on Xbox.
	// AUTO_OFFSET(Animation, MatrixB, "\x41\x8D\x51\x00\xE8\x72\x9A\x42\x00\x48\x8D\x15\x93\xFC\xC3\x00", "xxx?xxxxxxxxxxxx", ".text", ScanType::MovRegByte, 0);
	AUTO_OFFSET(Inventory, NestedCargo, "\x49\x8D\x96\x00\x00\x00\x00\x41\xB8\x20\x00\x00\x00\x48\x8D\x4C", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// Modbase::World — SetupModbasePatterns already registers the canonical
	// 1.29 sig (`48 8B 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 30`). The previous
	// 4C 8B 05 override here landed on an unrelated sister site that misses
	// on the Xbox build entirely. Removing the override so the SetupModbase
	// sig wins (the cheat's runtime sig_scanner uses the same one and hits
	// on both Steam and Xbox).
	// XBOX-PORTABLE 2026-07-15: Cross-platform pattern found on both Steam and Xbox.
	// Pattern: mov rdx,[rdi+0x1C8]; add rdx,0x2C (disp32 at byte 3)
	AUTO_OFFSET(Entity, VisualState, "\x48\x8B\x97\x00\x00\x00\x00\x48\x83\xC2\x2C\x48\x89\x6C\x24", "xxx????xxxxxxxx", ".text", ScanType::MovReg, 0);
	// Network::PlayerName — hardcoded at 0xF8 (pattern broken in 1.29)
	// The offset is already defined in offsets.h, skip signature scanning
	AUTO_OFFSET(Weapon, ChamberEntrySize, "\x89\xBB\x00\x00\x00\x00\x48\x89\xBB\x08\x01\x00\x00\x89\xBB\x10", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	// NOTE: Steam/Xbox have different surrounding code. Using Steam-only pattern.
	AUTO_OFFSET(Entity, FutureVisualState, "\x89\xBB\x00\x00\x00\x00\x48\x89\xBB\x28\x01\x00\x00\x89\xBB\x30", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	// Modbase::Tick — SetupModbasePatterns' `48 8B 05 ? ? ? ? 0F 57 C9 66 0F 6E 03`
	// is the canonical 1.29 sig. The 4C 8B 05 override here is a Steam-only
	// variant that doesn't exist on Xbox. Removed so the canonical sig wins.
	AUTO_OFFSET(HumanType, Realclassname, "\x80\xB9\x00\x00\x00\x00\x00\x48\x8B\xD9\x74\x1A\x48\x8B\x49\x78", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Network, ClientIdSize, "\x48\x89\x91\x00\x00\x00\x00\x33\xFF\x48\x89\x91\x60\x01\x00\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// XBOX-PORTABLE 2026-07-15: Cross-platform pattern - struct init sequence.
	// mov [rbx+0x180], rax; mov [rbx+0x188], eax (disp32 at byte 3)
	AUTO_OFFSET(Entity, Type, "\x48\x89\x83\x00\x00\x00\x00\x89\x83\x88\x01\x00\x00\x48\x89\x83", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Inventory, Hands, "\x49\x89\xB7\x00\x00\x00\x00\x89\x5A\x0C\x41\x89\x9F\xB8\x01\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Weapon, AttachmentsArray, "\x8B\x8E\x00\x00\x00\x00\x39\xAE\x34\x01\x00\x00\x76\x09\x44\x8B", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Inventory, ItemQuality, "\x44\x89\x89\x00\x00\x00\x00\x8B\xC3\x44\x89\x81\x90\x01\x00\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Inventory, SlotCountAlt, "\x41\xC7\x80\x00\x00\x00\x00\x06\x00\x00\x00\x41\x8B\x80\xC8\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Modbase, Landscape, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x89\x44\x24\x28\x48\x89\x44\x24", "xxx????xxxxxxxxx", ".text", ScanType::MovCs, 0);
	// Inventory::NestedInventory — `mov [rdi+disp32], ecx` followed by a
	// generic function epilogue. NOT Xbox-portable: epilogue is too common,
	// Xbox's first-match lands on a different site (Steam=0x650, Xbox-false=0x344).
	// Steam value is the engine ABI offset and applies to both. Not consumed
	// by the v15 cheat.
	AUTO_OFFSET(Inventory, NestedInventory, "\x89\x8F\x00\x00\x00\x00\x48\x8B\x5C\x24\x40\x48\x83\xC4\x30\x5F", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(World, WeatherController, "\x48\x8B\x81\x00\x00\x00\x00\x4C\x8B\x40\x20\xF3\x41\x0F\x10\x70", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x518 Xbox=0x518 — ABI confirmed identical).
	AUTO_OFFSET(HumanType, CleanName, "\x48\x8B\x8B\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x8B\x00\x05\x00\x00", "xxx????x????xxxxxxx", ".text", ScanType::MovReg, 0);
	// Network::ThirdPerson is hardcoded to 0x74 in Offsets.h (ADD_OFFSET_MANUAL).
	// The previous signature here resolved to 0x9C — a sibling DWORD field in
	// MissionHeader — and silently broke Force Third Person across the suite.
	// MissionHeader struct layout is engine ABI, not version-volatile compiled
	// code, so resolving via sig isn't worth the failure mode.
	AUTO_OFFSET(Ammo, InitSpeed, "\x49\x8D\xBF\x00\x00\x00\x00\x66\x0F\x1F\x84\x00\x00\x00\x00\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// XBOX-PORTABLE 2026-07-15: Cross-platform pattern using cmp access.
	// cmp byte ptr [rax+0x6DC], 0; jz +0x16; mov rax,[rbx]
	AUTO_OFFSET(Entity, NetworkId, "\x80\xB8\x00\x00\x00\x00\x00\x74\x16\x48\x8B\x03\x48\x8B\xCB\xFF", "xx?????xxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Infected, Skeleton, "\x48\x8D\x88\x00\x00\x00\x00\x48\x8B\x11\xFF\x12\x33\xFF\x44\x8B", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Camera, ProjectionD2, "\x8B\x87\x00\x00\x00\x00\x8B\x5B\x1C\x83\xE8\x01\x89\x87\xE0\x00", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Weapon, AttachmentsSize, "\x8B\x81\x00\x00\x00\x00\x05\xB8\x01\x00\x00\xC3\x48\x83\xE9\x20", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x350 Xbox=0x350 — ABI confirmed identical).
	AUTO_OFFSET(Network, GameVersion, "\x48\x89\x9F\x00\x00\x00\x00\x48\x89\x9F\x58\x03\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Entity, EntityDead, "\x88\x9F\x00\x00\x00\x00\x48\x8B\x5C\x24\x50\x48\x83\xC4\x40\x5F", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	// XBOX-PORTABLE 2026-07-15: Cross-platform pattern - struct init sequence.
	// mov [r?+0x308],r?; mov [r?+0x310],r?; mov [r?+0x318],r?
	AUTO_OFFSET(Network, ServerName, "\x48\x89\x00\x00\x00\x00\x00\x48\x89\x00\x10\x03\x00\x00\x48\x89", "xx?????xx?xxxxxx", ".text", ScanType::MovReg, 0);
	// NOTE: Pattern has hardcoded 8B 05 2B FC E8 00 RIP-relative offset - may not work on Xbox.
	// Wildcarding the RIP-relative part for cross-platform compatibility.
	AUTO_OFFSET(Ammo, AirFriction, "\x41\x89\x87\x00\x00\x00\x00\x8B\x05\x00\x00\x00\x00\x41\x89\x87", "xxx????xx????xxx", ".text", ScanType::MovReg, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0xE2 Xbox=0xE2 — ABI confirmed identical).
	AUTO_OFFSET(Entity, IsDead, "\xC6\x80\x00\x00\x00\x00\x02\x48\x8B\x06\xFF\x50\x30\x48\x8B\x00", "xx????xxxxxxxxx?", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Object_layout, MaterialCount, "\xF3\x0F\x10\x86\x00\x00\x00\x00\xF3\x0F\x11\x45\x74\xF3\x0F\x10", "xxxx????xxxxxxxx", ".text", ScanType::MovRegXmm, 0);
	AUTO_OFFSET(Object_layout, MaterialArray, "\x89\x87\x00\x00\x00\x00\x8B\x43\x28\x89\x87\x5C\x05\x00\x00\x8B", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x2010 Xbox=0x2010 — ABI confirmed identical).
	AUTO_OFFSET(World, SlowEntList, "\x49\x8D\x9E\x00\x00\x00\x00\x0F\x1F\x00\xBF\x40\x00\x00\x00", "xxx????xxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Ammo, Dispersion, "\x41\x39\x84\x0E\x00\x00\x00\x00\x74\x24\x41\x81\x8C\x0E\xD4\x01", "xxxx????xxxxxxxx", ".text", ScanType::MovRegXmm, 0);
	AUTO_OFFSET(Ammo, MagazineAmmoCount, "\x39\x9F\x00\x00\x00\x00\x76\x79\x4C\x8B\x97\xA0\x06\x00\x00\x44", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Weapon, ChamberArray, "\x49\x89\xAF\x00\x00\x00\x00\x49\x89\x9F\xC0\x08\x00\x00\x49\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// Updated 2026-07-15: Fixed mask length (16 bytes)
	AUTO_OFFSET(Ammo, MagazineCapacityA, "\x49\x8D\x8F\x00\x00\x00\x00\x33\xD2\x48\x89\x05\x00\x00\x00\x00", "xxx????xxxxx????", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Player, Skeleton, "\x48\x8B\x98\x00\x00\x00\x00\x4C\x8B\xA0\x00\x02\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, DayTime, "\x4C\x89\x83\x00\x00\x00\x00\x4C\x89\x83\x80\x29\x00\x00\x4C\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Player, InputController, "\x89\x81\x00\x00\x00\x00\x48\x89\x81\x04\x08\x00\x00\x48\x89\x81", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(World, GrassOffline, "\x4C\x89\x80\x00\x00\x00\x00\x48\x8D\x80\x00\x0C\x00\x00\x48\x83", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, GrassOnline, "\x48\x8D\x80\x00\x00\x00\x00\x48\x83\xEA\x40\x0F\x85\x11\xF9\xFF", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, EyeAccom, "\xF3\x0F\x10\x80\x00\x00\x00\x00\x0F\xC6\xC0\x00\xC7\x45\x48\x00", "xxxx????xxxxxxxx", ".text", ScanType::MovRegXmm, 0);
	// Updated 2026-07-15: Fixed mask - need 6 wildcards for offset+immediate
	AUTO_OFFSET(Ammo, FuseDistance, "\x66\xC7\x83\x00\x00\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00", "xxx??????xxx????", ".text", ScanType::MovReg, 0);
	// Animation::MatrixArray at +0xBE8 — bone matrix array pointer store.
	// Updated 2026-09-13: Ghidra analysis found unique pattern at RVA 0x4CCAC3:
	//   mov [rcx+0xBE8], esi; mov [rcx+0xBF8], r14; mov dword [rcx+0x08], ...
	// The consecutive stores to 0xBE8, 0xBF8, and 0x08 provide unique anchoring.
	AUTO_OFFSET(Animation, MatrixArray, "\x89\xB1\x00\x00\x00\x00\x4C\x89\xB1\xF8\x0B\x00\x00\xC7\x81\x08", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);

	// Animation::AnimationComp at +0x118 — skeleton->anim class pointer.
	// Updated 2026-09-13: Ghidra analysis found unique pattern at RVA 0x5FB29:
	//   mov [rbx+0x118], edi; mov [rbx+0x120], edi; mov [rbx+0x128], rdi
	// Matches community signature "48 89 BB 18 01 00 00 89 BB 20 01 00 00".
	AUTO_OFFSET(Animation, AnimationComp, "\x89\xBB\x18\x01\x00\x00\x89\xBB\x20\x01\x00\x00\x48\x89\xBB\x28", "xxxxxxxxxxxxxxxx", ".text", ScanType::MovRegSml, 0);

	// Animation::MatrixB at +0x54 — bone offset within matrix entry.
	// Community signature: "8B 43 54 8B 53 50 4C 8B 73 48" (mov eax,[rbx+0x54]; mov edx,[rbx+0x50]; mov r14,[rbx+0x48])
	// The disp8 is at byte 2 of the instruction (8B 43 [54]). MovRegByteSml reads *(BYTE*)(Instruction+2).
	AUTO_OFFSET(Animation, MatrixB, "\x8B\x43\x54\x8B\x53\x50\x4C\x8B\x73\x48", "xxxxxxxxxx", ".text", ScanType::MovRegByteSml, 0);
	AUTO_OFFSET(World, FarTableSize, "\x48\x89\xB7\x00\x00\x00\x00\x48\x89\xB7\xB8\x10\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Ammo, MagazineCapacityB, "\x44\x3B\x82\x00\x00\x00\x00\x0F\x83\xF5\x03\x00\x00\x41\x8B\xD0", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// NOTE: This pattern has hardcoded call offset. Using the working BulletList pattern instead.
	// AUTO_OFFSET(World, BulletTable, "\x48\x8D\x8B\x00\x00\x00\x00\xE8\xCA\x00\x00\x00\x48\x8D\x8B\x20", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// XBOX-PORTABLE 2026-07-15: Wildcarded modrm bytes (A9->? for Xbox AB compatibility).
	// Steam uses rcx base (A9), Xbox uses rbx base (AB) - same offset 0x2960.
	AUTO_OFFSET(World, LocalPlayer, "\x89\x00\x00\x00\x00\x00\x40\x88\x00\x64\x29\x00\x00\x48\x89\x00", "x?????xx?xxxxx??", ".text", ScanType::MovRegSml, 0);
	// XBOX-PORTABLE 2026-07-15: Wildcarded modrm bytes for Xbox compatibility.
	AUTO_OFFSET(World, PlayerOn, "\x48\x89\x00\x00\x00\x00\x00\x48\x89\x00\x70\x29\x00\x00\x48\x89", "xx?????xx?xxxxxx", ".text", ScanType::MovReg, 0);
	// XBOX-PORTABLE 2026-07-15: Wildcarded modrm bytes for Xbox compatibility.
	AUTO_OFFSET(World, TimeScale, "\x48\x89\x00\x00\x00\x00\x00\x48\x89\x00\x78\x29\x00\x00\x89\x00", "xx?????xx?xxxx??", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, BulletCount, "\x4C\x63\xA3\x00\x00\x00\x00\x8B\xEF\x4D\x85\xE4\x7E\x49\x48\x8B", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// NOTE: This pattern has hardcoded call offsets that differ between Steam/Xbox.
	// The SetupWorldPatterns version uses a shorter, more generic pattern.
	// AUTO_OFFSET(World, NearEntList, "\x48\x8D\x8F\x00\x00\x00\x00\xE8\x42\xA7\x00\x00\xE8\x3D\xA9\x1A", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x2018 Xbox=0x2018 — ABI confirmed identical).
	AUTO_OFFSET(World, SlowTableSize, "\x4C\x89\xBF\x00\x00\x00\x00\x44\x89\xBF\x20\x20\x00\x00\xE8\x00", "xxx????xxxxxxxx?", ".text", ScanType::MovReg, 0);
	// NOTE: Jle offset is version-dependent. Commented out for now.
	// AUTO_OFFSET(World, NearTableSize, "\x39\xB9\x00\x00\x00\x00\x0F\x8E\xE6\x00\x00\x00\x44\x8B\xF7\x48", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(World, FarEntList, "\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\x0C\x06\x48\x3B\xCD\x74\x17", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);

	// === 2026-06-10 batch: sigs from Ghidra agent analysis ===

	// Player::StatsContainer — the previous run matched +0x670 (a different
	// player field, likely a parallel sub-system pointer) instead of 0x6F0.
	// Both sites have the same `mov rcx,[rcx+disp]; test rcx,rcx; jne`
	// shape — too generic to disambiguate by code structure alone.
	// Pin the literal F0 06 00 00 in the sig so only the actual stats
	// container's load instruction is matched.
	AUTO_OFFSET(Player, StatsContainer,
		"\x48\x8B\x89\xF0\x06\x00\x00\x48\x85\xC9\x0F\x85",
		"xxxxxxxxxxxx",
		".text", ScanType::MovReg, 0);

	// PlayerStats::RecordValue @ +0x2C — known from PlayerStats::AddDelta.
	// Pattern: `addss xmm1, [r9+0x2C]; movss [r9+0x2C], xmm1; ret`
	// Bytes: F3 0F 58 49 [2C] F3 0F 11 49 2C C3
	// The disp8 (0x2C) is at byte 4 from pattern start.
	// MovRegXmmByte reads *(BYTE*)(Instruction+4). With offset=0: byte[4]=0x2C ✓
	AUTO_OFFSET_MANUAL(PlayerStats, RecordValue,
		"\xF3\x0F\x58\x49\x2C\xF3\x0F\x11\x49\x2C\xC3",
		"xxxxxxxxxxx",
		".text", ScanType::MovRegXmmByte, 0, 0);

	// Player::DamageManager — previous run resolved to 0x718, not 0x700,
	// likely because the agent's offset was approximate or there are
	// multiple zone managers. Pin exact for 0x700:
	AUTO_OFFSET(Player, DamageManager,
		"\x48\x8B\x89\x00\x07\x00\x00",
		"xxxxxxx",
		".text", ScanType::MovReg, 0);

	// Modbase::FovBase — engine FOV-singleton field offset (0x9C4) inside
	// the camera-pool record. SetFOV writer thunk at VA 0x140958620:
	//   F3 0F 11 89 C4 09 00 00       movss [rcx+0x9C4],xmm1
	// MovRegXmm reads the disp32 starting at instruction+4 (after the
	// SSE prefix + opcode + modrm). Manual mode locks the value as a
	// constant in case the resolver fails.
	AUTO_OFFSET_MANUAL(Modbase, FovBase,
		"\xF3\x0F\x11\x89\xC4\x09\x00\x00\x4C\x8D\x05",
		"xxxxxxxxxxx",
		".text", ScanType::MovRegXmm, 0, 0);

	// Modbase::ScopeFovCtx — FOV resolver context at modbase + 0x4264920.
	// The resolver function at VA 0x4B7640 loads it via:
	//   48 8B 05 ? ? ? ?              mov rax,[rip+disp32]
	//   F3 44 0F 10 25 ? ? ? ?        movss xmm12,[rip+default_0.74176f]
	// Currently unique in 1.29.
	AUTO_OFFSET(Modbase, ScopeFovCtx,
		"\x48\x8B\x05\x00\x00\x00\x00\xF3\x44\x0F\x10\x25\x00\x00\x00\x00\x44",
		"xxx????xxxxx????x",
		".text", ScanType::MovCs, 0);
}




bool Updater::SetupPatterns() {
	SetupModbasePatterns();
	SetupNetworkPatterns();
	SetupPlayerIdentityPatterns();
	SetupWorldPatterns();
	SetupHumanPatterns();
	SetupDayZInfectedPatterns();
	SetupHumanTypePatterns();
	SetupDayZLocalPatterns();
	SetupDayZPlayerPatterns();
	SetupDayZPlayerInventoryPatterns();
	SetupInventoryItemPatterns();
	SetupWeaponPatterns();
	SetupWeaponInventoryPatterns();
	SetupMagazinePatterns();
	SetupAmmoTypePatterns();
	SetupSkeletonPatterns();
	SetupAnimClassPatterns();
	SetupCameraPatterns();
	SetupVisualStatePatterns();

	// v16 extended pattern groups
	SetupEntityExtendedPatterns();
	SetupCameraExtendedPatterns();
	SetupDamageManagerPatterns();
	SetupInputControllerPatterns();
	SetupWeatherPatterns();
	SetupGrassRendererPatterns();
	SetupWorldExtendedPatterns();
	SetupNetworkExtendedPatterns();
	SetupWeaponExtendedPatterns();
	SetupAmmoTypeExtendedPatterns();
	SetupFunctionRVAPatterns();
	SetupModbaseExtendedPatterns();
	SetupFreecamPatterns();
	SetupHumanCommandPatterns();
	SetupPhysicsBodyPatterns();

	// SetupExtraPatterns runs LAST so its freshly-extracted 1.29 signatures
	// overwrite any stale entries the per-class Setup* functions registered
	// for the same offset name. m_Scans is keyed by "Klass::Name" with
	// last-write-wins semantics: putting Extra first meant SetupWorldPatterns
	// clobbered our new World::LocalPlayer pattern with the old TraceMovReg
	// scan that resolves to 0x2958 instead of the correct 0x2960.
	SetupExtraPatterns();

	return true;
}

bool Updater::Init() {

	if (!AllocateModule())
		return false;

	if (!SetupPatterns())
		return false;

	return true;
}

bool Updater::Scan() {
for (auto& entry : m_Scans) {
		entry.second.Scan(m_Module, m_Allocated);
	}

	return true;
}


bool Updater::Release() {

	// Group scan results into resolved / failed lists so the log shows a
	// stable, sorted output (entries in std::unordered_map come back in
	// hash-bucket order which is platform-dependent and annoying to diff).
	struct Row { std::string name; INT64 value; bool ok; };
	std::vector<Row> rows;
	rows.reserve(m_Scans.size());
	for (auto& entry : m_Scans) {
		Row r{entry.first, 0, false};
		if (entry.second.UpdateReference()) {
			r.value = entry.second.GetOffset();
			r.ok = true;
		}
		rows.push_back(std::move(r));
	}
	// Sort: resolved entries first (alphabetical), failures last (alphabetical).
	// Comparator returns true when a should come before b — resolved beats
	// failed, then ties break on name.
	std::sort(rows.begin(), rows.end(),
		[](const Row& a, const Row& b) {
			if (a.ok != b.ok) return a.ok && !b.ok;   // resolved first
			return a.name < b.name;
		});

	int hit = 0, miss = 0;
	for (auto& r : rows) {
		if (r.ok) ++hit; else ++miss;
	}
	TLOG("[UPDATER] === RESOLVED (%d) ===\n", hit);
	for (auto& r : rows) {
		if (!r.ok) continue;
		TLOG("[UPDATER] %-36s -> 0x%llX\n",
			r.name.c_str(), static_cast<unsigned long long>(r.value));
	}
	if (miss > 0) {
		TLOG("[UPDATER] === FAILED (%d) ===\n", miss);
		for (auto& r : rows) {
			if (r.ok) continue;
			TLOG("[UPDATER] Failed to get offset: %s\n", r.name.c_str());
		}
	}
	TLOG("[UPDATER] --- summary: resolved=%d failed=%d total=%d ---\n",
		hit, miss, hit + miss);

	m_Scans.clear();
	(void)DeallocateModule();
	return miss == 0;
}
