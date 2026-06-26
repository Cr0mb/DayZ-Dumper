#pragma once

#include <unordered_map>
#include <string>
#include <cstdio>

// Tee output to both the console and a log file next to Updater.exe. Used
// instead of the prior freopen-stdout-to-dump.log trick so users see every
// line in real time AND get a persistent log. Open in Entry.cpp before
// Init(); flushes on every line so the log survives a mid-run crash.
namespace teelog {
    void Open();      // creates <Updater.exe-folder>\dump.log (overwrites prior)
    void Close();
    void Printf(const char* fmt, ...);   // -> stdout AND log file
}

// Drop-in for printf throughout the dumper. Whenever we want a line in the
// permanent log AND on the console, call TLOG instead of printf.
#define TLOG(...)  ::teelog::Printf(__VA_ARGS__)

enum class ScanType {
	MovReg,
	MovRegByte,
	MovRegSml,
	MovRegByteSml,
	MovRegXmm,
	MovRegXmmLrg,
	MovRegXmmByte,
	MovRegXmmLrgByte,
	TraceMovReg,		/* Unstable AF */
	TraceMovRegByte,	/* Unstable AF */
	MovCs,
	CmpCs,
};

class AutoOffset {
private:
	PBYTE m_Pattern;
	const char* m_Mask;
	const char* m_Section;
	INT64 m_Offset;
	INT64* m_Reference;
	ScanType m_Type;
	UINT32 m_InstructionOffset;
	INT32 m_LastOffset;

protected:
	INT64 ResolveMovCs(UINT64 Module, UINT64 Instruction);
	INT64 ResolveCmpCs(UINT64 Module, UINT64 Instruction);
	INT64 ResovleMovRegXmm(UINT64 Module, UINT64 Instruction);
	INT64 ResolveMovRegXmmLrg(UINT64 Module, UINT64 Instruction);
	INT64 ResovleMovRegXmmByte(UINT64 Module, UINT64 Instruction);
	INT64 ResovleMovRegXmmLrgByte(UINT64 Module, UINT64 Instruction);
	INT64 ResolveMovReg(UINT64 Module, UINT64 Instruction);
	INT64 ResolveMovRegByte(UINT64 Module, UINT64 Instruction);
	INT64 ResolveMovRegSml(UINT64 Module, UINT64 Instruction);
	INT64 ResovleMovRegByteSml(UINT64 Module, UINT64 Instruction);
	INT64 ResolveTraceMovReg(UINT64 Module, UINT64 Instruction);
	INT64 ResolveTraceMovRegByte(UINT64 Module, UINT64 Instruction);
	bool ResolveOffset(UINT64 Module, UINT64 Instruction);

public:
	bool UpdateReference();
	void SetReference(INT64* Reference);
	void SetPattern(PBYTE Pattern);
	void SetMask(const char* Mask);
	void SetSection(const char* Section);
	void SetType(ScanType Type);
	void SetOffset(UINT32 Offset);
	void SetLastOffset(INT32 Offset);

	INT64 GetOffset();

	virtual bool Scan(UINT64 Module, PBYTE Allocated);
};

#define AUTO_OFFSET(Klass, Name, Pattern, Mask, Section, Type, Offset)	\
	AutoOffset Klass##_##Name;										\
	Klass##_##Name.SetPattern((PBYTE)Pattern);					\
	Klass##_##Name.SetMask(Mask);									\
	Klass##_##Name.SetSection(Section);							\
	Klass##_##Name.SetType(Type);									\
	Klass##_##Name.SetReference(&Offsets::Klass::Name);			\
	Klass##_##Name.SetOffset(Offset);								\
	m_Scans[#Klass "::" #Name] = Klass##_##Name;

#define AUTO_OFFSET_MANUAL(Klass, Name, Pattern, Mask, Section, Type, Offset, LastOffset)	\
	AutoOffset Klass##_##Name;										\
	Klass##_##Name.SetPattern((PBYTE)Pattern);					\
	Klass##_##Name.SetMask(Mask);									\
	Klass##_##Name.SetSection(Section);							\
	Klass##_##Name.SetType(Type);									\
	Klass##_##Name.SetReference(&Offsets::Klass::Name);			\
	Klass##_##Name.SetOffset(Offset);								\
	Klass##_##Name.SetLastOffset(LastOffset);						\
	m_Scans[#Klass "::" #Name] = Klass##_##Name;

class Updater {
public:
	std::unordered_map<std::string, AutoOffset> m_Scans;

	UINT64 m_Module;
	PBYTE m_Allocated;
	// When non-empty, AllocateModule LoadLibraryA's this path instead of
	// finding DayZ_x64.exe in the running process list. Set via Entry's
	// command-line arg.
	char m_PathOverride[MAX_PATH] = {};

	// Platform selector. Auto = try LoadLibraryA first (Steam path), fall
	// back to NeacSafe64 live-memory dump on failure (Xbox / Game Pass path).
	// Steam = LoadLibraryA only; Xbox = NeacSafe64 only.
	enum class Platform { Auto, Steam, Xbox };
	Platform m_Platform = Platform::Auto;

	// When non-empty, after a successful NeacSafe64 reconstruction we also
	// write the reconstructed image to this path for static analysis. Set
	// via --save-pe <path>. Ignored on the Steam / LoadLibraryA path.
	char m_SavePeTo[MAX_PATH] = {};

private:
	bool AllocateModule();
	bool DeallocateModule();

private: /* sub setuppatterns here :p */
	void SetupModbasePatterns();
	void SetupNetworkPatterns();
	void SetupPlayerIdentityPatterns();
	void SetupWorldPatterns();
	void SetupHumanPatterns();
	void SetupDayZInfectedPatterns();
	void SetupHumanTypePatterns();
	void SetupDayZLocalPatterns();
	void SetupDayZPlayerPatterns();
	void SetupDayZPlayerInventoryPatterns();
	void SetupInventoryItemPatterns();
	void SetupWeaponPatterns();
	void SetupWeaponInventoryPatterns();
	void SetupMagazinePatterns();
	void SetupAmmoTypePatterns();
	void SetupSkeletonPatterns();
	void SetupAnimClassPatterns();
	void SetupCameraPatterns();
	void SetupVisualStatePatterns();

private:
	void SetupExtraPatterns();
	bool SetupPatterns();

public:
	bool Init();
	bool Scan();
	bool Release();

};

extern Updater* g_Updater;