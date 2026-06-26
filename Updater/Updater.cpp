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
	AUTO_OFFSET(Modbase, FOV_Context, "\x48\x8B\x05\x00\x00\x00\x00\x48\x0F\x45\x05\x21\x75\xB5\x00\x48", "xxx????xxxxxxxxx", ".text", ScanType::MovCs, 0);
	AUTO_OFFSET(Modbase, Network, "\x48\x89\x3D\x00\x00\x00\x00\x48\x8D\x05\xA8\x07\xFE\x00\xC7\x05", "xxx????xxxxxxxxx", ".text", ScanType::MovCs, 0);
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

	// OUTDATED: Modbase::ScriptContext — no replacement in .
	// AUTO_OFFSET(Modbase, ScriptContext,
	// 	"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\xD9\x4C\x8B\x88\x00\x00\x00\x00",
	// 	"xxx????xxxxxx????",
	// 	".text", ScanType::MovCs, 0);
}



void Updater::SetupNetworkPatterns() {
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x350 Xbox=0x350 — ABI confirmed identical).
	AUTO_OFFSET(Network, GameVersion, "\x48\x89\x9F\x00\x00\x00\x00\x48\x89\x9F\x58\x03\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Network, Ping, "\x48\x8D\x8F\x00\x00\x00\x00\x48\x8D\x05\x96\xF1\xAC\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Network, ServerName, "\x48\x89\xB7\x00\x00\x00\x00\x48\x89\x07\x48\x8D\x8F\x3C\x03\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);

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

	AUTO_OFFSET(World, NearEntList,
		"\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\x14\x06\x48\x3B\xD5",
		"xxx????xxxxxxx",
		".text", ScanType::MovReg, 0);

	AUTO_OFFSET(World, FarEntList,
		"\x48\x8B\x83\x00\x00\x00\x00\x49\x8B\x0C\x06\x48\x3B\xCD\x74\x17\x80\xB9\x00\x00\x00\x00\x00\x75\x0E\x41\xB8\x00\x00\x00\x00\x0F\x28\xCE\xE8\x00\x00\x00\x00\xFF\xC6\x49\x83\xC6\x08\x3B\xB3\x00\x00\x00\x00\x7C\xCB",
		"xxx????xxxxxxxxxxx?????xxxx????xxxx????xxxxxxxx????xx",
		".text", ScanType::MovReg, 0);

	AUTO_OFFSET(World, Camera,
		"\x4C\x8B\x83\x00\x00\x00\x00\x4C\x8B\x11\x48\x89\x70\x08",
		"xxx????xxxxxxx",
		".text", ScanType::MovReg, 0);

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
	AUTO_OFFSET(DayZInfected, Skeleton,
		"\x44\x89\xAF\x00\x00\x00\x00\x44\x88\xAF\x00\x00\x00\x00\x4C\x89\xAF",
		"xxx????xxx????xxx",
		".text", ScanType::MovReg, 0);
}


void Updater::SetupHumanTypePatterns() {
	AUTO_OFFSET(HumanType, CleanNameInternal, "\x48\x8D\x9F\x00\x00\x00\x00\x48\x8B\xCB\xE8\x53\xD0\x2E\x00\x48", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);

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
	AUTO_OFFSET(Weapon, AmmoCapacityA, "\x49\x8D\x8F\x00\x00\x00\x00\x33\xD2\x48\x89\x05\xAA\x86\xE2\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
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
	AUTO_OFFSET(VisualState, InverseTransform, "\x89\x8B\x00\x00\x00\x00\x8B\x4A\x04", "xx????xxx", ".text", ScanType::MovRegSml, 0);

}



void Updater::SetupExtraPatterns() {
	AUTO_OFFSET(Ammo, IndirectHitRange, "\x00\x00\x00\x48\x63\x54\x24\x38\x48\x8D\x0D\x41\x05\x27\x04\x48", "???xxxxxxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Camera, ViewportSize, "\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x8B\x0D\xAA\xFE\x24\x04\xBA", "xxxxx????xxxxxxx", ".text", ScanType::MovRegXmmLrg, 0);
	AUTO_OFFSET(Network, ManagerNetworkClient, "\x89\x42\x00\x0F\x11\x42\x58\x89\x42\x78\x0F\x11\x82\x80\x00\x00", "xx?xxxxxxxxxxxxx", ".text", ScanType::MovRegByteSml, 0);
	AUTO_OFFSET(Network, Crosshair, "\x89\x82\x00\x00\x00\x00\x0F\x11\x82\xA8\x00\x00\x00\x89\x82\xC8", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Animation, AnimationComp, "\x89\x82\x00\x00\x00\x00\x0F\x11\x82\x20\x01\x00\x00\x89\x82\x40", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
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
	AUTO_OFFSET(Inventory, NestedCargoCount, "\x41\x8D\x51\x00\xE8\x02\x9D\x42\x00\x48\x8D\x15\x2B\xFE\xC3\x00", "xxx?xxxxxxxxxxxx", ".text", ScanType::MovRegByte, 0);
	AUTO_OFFSET(Animation, MatrixB, "\x41\x8D\x51\x00\xE8\x72\x9A\x42\x00\x48\x8D\x15\x93\xFC\xC3\x00", "xxx?xxxxxxxxxxxx", ".text", ScanType::MovRegByte, 0);
	AUTO_OFFSET(Inventory, NestedCargo, "\x49\x8D\x96\x00\x00\x00\x00\x41\xB8\x20\x00\x00\x00\x48\x8D\x4C", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	// Modbase::World — SetupModbasePatterns already registers the canonical
	// 1.29 sig (`48 8B 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 30`). The previous
	// 4C 8B 05 override here landed on an unrelated sister site that misses
	// on the Xbox build entirely. Removing the override so the SetupModbase
	// sig wins (the cheat's runtime sig_scanner uses the same one and hits
	// on both Steam and Xbox).
	AUTO_OFFSET(Entity, VisualState, "\x48\x8B\x87\x00\x00\x00\x00\x48\x83\xC0\x2C\xF3\x0F\x10\x00\xF3", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Network, PlayerName, "\x48\x89\xBB\x00\x00\x00\x00\x89\xBB\x00\x01\x00\x00\x48\x89\xBB", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Weapon, ChamberEntrySize, "\x89\xBB\x00\x00\x00\x00\x48\x89\xBB\x08\x01\x00\x00\x89\xBB\x10", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Entity, FutureVisualState, "\x89\xBB\x00\x00\x00\x00\x48\x89\xBB\x28\x01\x00\x00\x89\xBB\x30", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	// Modbase::Tick — SetupModbasePatterns' `48 8B 05 ? ? ? ? 0F 57 C9 66 0F 6E 03`
	// is the canonical 1.29 sig. The 4C 8B 05 override here is a Steam-only
	// variant that doesn't exist on Xbox. Removed so the canonical sig wins.
	AUTO_OFFSET(HumanType, Realclassname, "\x80\xB9\x00\x00\x00\x00\x00\x48\x8B\xD9\x74\x1A\x48\x8B\x49\x78", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Network, ClientIdSize, "\x48\x89\x91\x00\x00\x00\x00\x33\xFF\x48\x89\x91\x60\x01\x00\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Entity, Type, "\x89\x83\x00\x00\x00\x00\x48\x8B\xCB\x48\x8B\x03\xFF\x50\x50\xEB", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
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
	AUTO_OFFSET(Entity, NetworkId, "\x89\x83\x00\x00\x00\x00\x45\x33\xC0\x8B\x41\x1C\x89\x83\xE0\x06", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Infected, Skeleton, "\x48\x8D\x88\x00\x00\x00\x00\x48\x8B\x11\xFF\x12\x33\xFF\x44\x8B", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Camera, ProjectionD2, "\x8B\x87\x00\x00\x00\x00\x8B\x5B\x1C\x83\xE8\x01\x89\x87\xE0\x00", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Weapon, AttachmentsSize, "\x8B\x81\x00\x00\x00\x00\x05\xB8\x01\x00\x00\xC3\x48\x83\xE9\x20", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x350 Xbox=0x350 — ABI confirmed identical).
	AUTO_OFFSET(Network, GameVersion, "\x48\x89\x9F\x00\x00\x00\x00\x48\x89\x9F\x58\x03\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Entity, EntityDead, "\x88\x9F\x00\x00\x00\x00\x48\x8B\x5C\x24\x50\x48\x83\xC4\x40\x5F", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Network, ServerName, "\x48\x89\xB7\x00\x00\x00\x00\x48\x89\x07\x48\x8D\x8F\x3C\x03\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Ammo, AirFriction, "\x41\x89\x87\x00\x00\x00\x00\x8B\x05\x2B\xFC\xE8\x00\x41\x89\x87", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0xE2 Xbox=0xE2 — ABI confirmed identical).
	AUTO_OFFSET(Entity, IsDead, "\xC6\x80\x00\x00\x00\x00\x02\x48\x8B\x06\xFF\x50\x30\x48\x8B\x00", "xx????xxxxxxxxx?", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Object_layout, MaterialCount, "\xF3\x0F\x10\x86\x00\x00\x00\x00\xF3\x0F\x11\x45\x74\xF3\x0F\x10", "xxxx????xxxxxxxx", ".text", ScanType::MovRegXmm, 0);
	AUTO_OFFSET(Object_layout, MaterialArray, "\x89\x87\x00\x00\x00\x00\x8B\x43\x28\x89\x87\x5C\x05\x00\x00\x8B", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x2010 Xbox=0x2010 — ABI confirmed identical).
	AUTO_OFFSET(World, SlowEntList, "\x49\x8D\x9E\x00\x00\x00\x00\x0F\x1F\x00\xBF\x40\x00\x00\x00", "xxx????xxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Ammo, Dispersion, "\x41\x39\x84\x0E\x00\x00\x00\x00\x74\x24\x41\x81\x8C\x0E\xD4\x01", "xxxx????xxxxxxxx", ".text", ScanType::MovRegXmm, 0);
	AUTO_OFFSET(Ammo, MagazineAmmoCount, "\x39\x9F\x00\x00\x00\x00\x76\x79\x4C\x8B\x97\xA0\x06\x00\x00\x44", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(Weapon, ChamberArray, "\x49\x89\xAF\x00\x00\x00\x00\x49\x89\x9F\xC0\x08\x00\x00\x49\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Ammo, MagazineCapacityA, "\x49\x8D\x8F\x00\x00\x00\x00\x33\xD2\x48\x89\x05\xAA\x86\xE2\x00", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Player, Skeleton, "\x48\x8B\x98\x00\x00\x00\x00\x4C\x8B\xA0\x00\x02\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, DayTime, "\x4C\x89\x83\x00\x00\x00\x00\x4C\x89\x83\x80\x29\x00\x00\x4C\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Player, InputController, "\x89\x81\x00\x00\x00\x00\x48\x89\x81\x04\x08\x00\x00\x48\x89\x81", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(World, GrassOffline, "\x4C\x89\x80\x00\x00\x00\x00\x48\x8D\x80\x00\x0C\x00\x00\x48\x83", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, GrassOnline, "\x48\x8D\x80\x00\x00\x00\x00\x48\x83\xEA\x40\x0F\x85\x11\xF9\xFF", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, EyeAccom, "\xF3\x0F\x10\x80\x00\x00\x00\x00\x0F\xC6\xC0\x00\xC7\x45\x48\x00", "xxxx????xxxxxxxx", ".text", ScanType::MovRegXmm, 0);
	AUTO_OFFSET(Ammo, FuseDistance, "\x66\xC7\x83\x00\x00\x00\x00\xFF\x00\x48\x8B\x05\xD9\x8A\xE0\x03", "xxx??xxxxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Animation, MatrixArray, "\x4C\x89\xB1\x00\x00\x00\x00\x4C\x89\xB1\xF8\x0B\x00\x00\xC7\x81", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, FarTableSize, "\x48\x89\xB7\x00\x00\x00\x00\x48\x89\xB7\xB8\x10\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(Ammo, MagazineCapacityB, "\x44\x3B\x82\x00\x00\x00\x00\x0F\x83\xF5\x03\x00\x00\x41\x8B\xD0", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, BulletTable, "\x48\x8D\x8B\x00\x00\x00\x00\xE8\xCA\x00\x00\x00\x48\x8D\x8B\x20", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, LocalPlayer, "\x89\xA9\x00\x00\x00\x00\x40\x88\xA9\x64\x29\x00\x00\x48\x89\xA9", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
	AUTO_OFFSET(World, PlayerOn, "\x48\x89\xA9\x00\x00\x00\x00\x48\x89\xA9\x70\x29\x00\x00\x48\x89", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, TimeScale, "\x48\x89\xA9\x00\x00\x00\x00\x48\x89\xA9\x78\x29\x00\x00\x89\xA9", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, BulletCount, "\x4C\x63\xA3\x00\x00\x00\x00\x8B\xEF\x4D\x85\xE4\x7E\x49\x48\x8B", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, NearEntList, "\x48\x8D\x8F\x00\x00\x00\x00\xE8\x42\xA7\x00\x00\xE8\x3D\xA9\x1A", "xxx????xxxxxxxxx", ".text", ScanType::MovReg, 0);
		// XBOX-PORTABLE 2026-06-25: relaxed to match Game Pass codegen (Steam=0x2018 Xbox=0x2018 — ABI confirmed identical).
	AUTO_OFFSET(World, SlowTableSize, "\x4C\x89\xBF\x00\x00\x00\x00\x44\x89\xBF\x20\x20\x00\x00\xE8\x00", "xxx????xxxxxxxx?", ".text", ScanType::MovReg, 0);
	AUTO_OFFSET(World, NearTableSize, "\x39\xB9\x00\x00\x00\x00\x0F\x8E\xE6\x00\x00\x00\x44\x8B\xF7\x48", "xx????xxxxxxxxxx", ".text", ScanType::MovRegSml, 0);
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

	// PlayerStats::RecordValue @ +0x2C — well-known from PlayerStats::AddDelta
	// at VA 0x6ABA30. Hard-coded because we already know the exact value
	// from Ghidra trace — no sig extraction needed; we use a known-match
	// pattern just to confirm presence then write the manual offset.
	AUTO_OFFSET_MANUAL(PlayerStats, RecordValue,
		"\xF3\x0F\x58\x49\x2C\xF3\x0F\x11\x49\x2C\xC3",
		"xxxxxxxxxxx",
		".text", ScanType::MovReg, 0, 0x2C);

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
