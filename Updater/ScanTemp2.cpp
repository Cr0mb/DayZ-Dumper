// ScanTemp2.cpp — Scan unexplored .text regions for unique function prologues
// Build:
//   cd /d "D:\GHaxLabs\GHaxLabsV17\DayZ-Dumper_v15"
//   call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
//   cl /std:c++17 /O2 /EHsc /Fe"x64\Release\ScanTemp2.exe" "Updater\ScanTemp2.cpp" /I"Updater" /link /SUBSYSTEM:CONSOLE
//
// Run:
//   cd /d "D:\GHaxLabs\GHaxLabsV17\DayZ-Dumper_v15\x64\Release"
//   ScanTemp2.exe

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <set>
#include <string>
#include <algorithm>

// ── Process helpers ──────────────────────────────────────────────────────

static bool GetProcessId(const char* name, DWORD* pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (!_stricmp(pe.szExeFile, name)) { *pid = pe.th32ProcessID; CloseHandle(snap); return true; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return false;
}

static bool GetModuleInfo(DWORD pid, const char* modName, UINT64* base, SIZE_T* size) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            if (!_stricmp(me.szModule, modName)) {
                *base = (UINT64)me.modBaseAddr;
                *size = me.modBaseSize;
                CloseHandle(snap);
                return true;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return false;
}

// ── PE helpers ───────────────────────────────────────────────────────────

struct SectionInfo {
    UINT64 rva;
    SIZE_T virtualSize;
    BYTE*  rawData;      // pointer into allocated image
    SIZE_T rawSize;
};

static bool FindSection(BYTE* imageBase, const char* name, SectionInfo* out) {
    auto dos = (IMAGE_DOS_HEADER*)imageBase;
    auto nt  = (IMAGE_NT_HEADERS*)(imageBase + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)sec[i].Name, name, 8) == 0) {
            out->rva         = sec[i].VirtualAddress;
            out->virtualSize = sec[i].Misc.VirtualSize;
            out->rawData     = imageBase + sec[i].VirtualAddress;
            out->rawSize     = sec[i].SizeOfRawData;
            return true;
        }
    }
    return false;
}

// ── Uniqueness check ─────────────────────────────────────────────────────

static bool IsUniqueInText(BYTE* textBase, SIZE_T textSize, BYTE* pattern, int len, BYTE* excludeAddr) {
    int hits = 0;
    for (SIZE_T i = 0; i + len <= textSize; ++i) {
        if (memcmp(textBase + i, pattern, len) == 0) {
            ++hits;
            if (hits > 1) return false;
        }
    }
    return hits == 1;
}

// ── Region descriptor ────────────────────────────────────────────────────

struct Region {
    DWORD startRVA;
    DWORD endRVA;
    const char* label;
};

static const Region g_regions[] = {
    { 0x01000,  0x030000, "VeryEarly"   },  // CRT init, TLS callbacks
    { 0x0ACD00, 0x0D0000, "NetEarly"    },  // between network and early
    { 0x100000, 0x140000, "FloatEarly"  },  // between early float funcs and player
    { 0x200000, 0x210000, "Gap200"      },  // small gap
    { 0x300000, 0x340000, "ScriptMid"   },  // gap between script and mid
    { 0x3D0000, 0x400000, "Gap3D"       },  // gap
    { 0x4A0000, 0x4C0000, "InfPlayer"   },  // gap between infected and player
    { 0x540000, 0x580000, "Gap54"       },  // gap
    { 0x580000, 0x5C0000, "Gap58"       },  // gap
    { 0x5C0000, 0x600000, "Gap5C"       },  // gap
    { 0x6C0000, 0x700000, "Gap6C"       },  // gap
    { 0x8A0000, 0x920000, "HealthPhys"  },  // gap between health and physics
    { 0x9B0000, 0xA00000, "Gap9B"       },  // gap
    { 0xC00000, 0xC01000, "TextEnd"     },  // very end of .text
};

// ── Prologue detection ───────────────────────────────────────────────────

// Check if byte looks like a function prologue start
static bool IsPrologueStart(BYTE* p) {
    // Common x64 prologue patterns:
    // push rbp (55), push rbx (53), push rsi (56), push rdi (57)
    // push r12-r15 (41 54-57)
    // sub rsp, imm (48 81 EC / 48 83 EC)
    // mov [rsp+...], reg (48 89 ...)
    // mov rax, rsp (48 8B C4)
    // lea rax, [rip+...] (48 8D 05 ...)
    // ret-prefixed thunks: C3 followed by CC
    // xorps xmm0,xmm0 (0F 57 C0)
    // test rcx,rcx (48 85 C9)
    // cmp al, imm (3C xx)
    // mov eax,[rcx+...] (8B 41 ...)
    // Various other entry patterns

    // Must start with a valid instruction prefix
    BYTE b0 = p[0];

    // Single-byte pushes
    if (b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57)
        return true;

    // REX prefix pushes: 40 53, 40 55, etc.
    if (b0 == 0x40 && (p[1] == 0x53 || p[1] == 0x55 || p[1] == 0x56 || p[1] == 0x57))
        return true;

    // REX.W + sub rsp: 48 83 EC / 48 81 EC
    if (b0 == 0x48 && (p[1] == 0x83 || p[1] == 0x81) && p[2] == 0xEC)
        return true;

    // mov rax, rsp: 48 8B C4
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xC4)
        return true;

    // mov [rsp+...], reg: 48 89 5C 24 / 48 89 74 24 / 48 89 4C 24 / 48 89 6C 24
    if (b0 == 0x48 && p[1] == 0x89 && (p[2] == 0x5C || p[2] == 0x74 || p[2] == 0x4C || p[2] == 0x6C) && p[3] == 0x24)
        return true;

    // lea rax, [rip+...]: 48 8D 05
    if (b0 == 0x48 && p[1] == 0x8D && p[2] == 0x05)
        return true;

    // ret thunk: C3 CC
    if (b0 == 0xC3 && p[1] == 0xCC)
        return true;

    // xorps xmm0,xmm0: 0F 57 C0
    if (b0 == 0x0F && p[1] == 0x57 && p[2] == 0xC0)
        return true;

    // test rcx,rcx: 48 85 C9
    if (b0 == 0x48 && p[1] == 0x85 && p[2] == 0xC9)
        return true;

    // cmp al, imm: 3C xx
    if (b0 == 0x3C)
        return true;

    // mov eax,[rcx+...]: 8B 41
    if (b0 == 0x8B && (p[1] & 0xF8) == 0x40)
        return true;

    // 48 8B C1 (mov rax, rcx)
    if (b0 == 0x48 && p[1] == 0x8B && (p[2] & 0xF8) == 0xC0)
        return true;

    // 4C 8B DC (mov r11, rsp)
    if (b0 == 0x4C && p[1] == 0x8B && p[2] == 0xDC)
        return true;

    // sub rsp, imm32 via 48 81 EC
    if (b0 == 0x48 && p[1] == 0x81 && p[2] == 0xEC)
        return true;

    // lea rbp, [rsp-...]: 48 8D AC 24 / 48 8D A8
    if (b0 == 0x48 && p[1] == 0x8D && (p[2] == 0xAC || p[2] == 0xA8))
        return true;

    // 48 83 EC (sub rsp, imm8)
    if (b0 == 0x48 && p[1] == 0x83 && p[2] == 0xEC)
        return true;

    // 8B 02 (mov eax, [rdx]) — entry pattern
    if (b0 == 0x8B && p[1] == 0x02)
        return true;

    // 85 D2 (test edx, edx) — entry pattern
    if (b0 == 0x85 && p[1] == 0xD2)
        return true;

    // 48 85 D2 (test rdx, rdx)
    if (b0 == 0x48 && p[1] == 0x85 && p[2] == 0xD2)
        return true;

    // 48 89 4C 24 (mov [rsp+...], rcx)
    if (b0 == 0x48 && p[1] == 0x89 && p[2] == 0x4C && p[3] == 0x24)
        return true;

    // 48 89 54 24 (mov [rsp+...], rdx)
    if (b0 == 0x48 && p[1] == 0x89 && p[2] == 0x54 && p[3] == 0x24)
        return true;

    // F3 0F 10 (movss xmm, [mem]) — float function entry
    if (b0 == 0xF3 && p[1] == 0x0F && p[2] == 0x10)
        return true;

    // 48 83 EC 28 (sub rsp, 0x28)
    // already covered by 48 83 EC above

    // 83 79 (cmp dword [rcx+...], imm8) — entry pattern
    if (b0 == 0x83 && p[1] == 0x79)
        return true;

    // C6 81 (mov byte [rcx+...], imm8) — entry pattern
    if (b0 == 0xC6 && p[1] == 0x81)
        return true;

    // 89 41 (mov [rcx+...], eax)
    if (b0 == 0x89 && p[1] == 0x41)
        return true;

    // 44 89 4C 24 (mov [rsp+...], r9d)
    if (b0 == 0x44 && p[1] == 0x89 && p[2] == 0x4C && p[3] == 0x24)
        return true;

    // 44 8B (mov r8, ...)
    if (b0 == 0x44 && p[1] == 0x8B)
        return true;

    // 48 8B 01 (mov rax, [rcx])
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0x01)
        return true;

    // 48 8B C4 variants
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xC4)
        return true;

    // 48 8B 41 (mov rax, [rcx+...])
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0x41)
        return true;

    // 48 89 5C 24 08 (mov [rsp+8], rbx) — very common prologue
    if (b0 == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24)
        return true;

    // 0F 57 C0 (xorps xmm0, xmm0)
    if (b0 == 0x0F && p[1] == 0x57 && p[2] == 0xC0)
        return true;

    // 80 B9 (cmp byte [rcx+...], imm8)
    if (b0 == 0x80 && p[1] == 0xB9)
        return true;

    // 8B 40 (mov eax, [rax+...])
    if (b0 == 0x8B && p[1] == 0x40)
        return true;

    // 8C 41 (sbb cl, [rcx-...])
    if (b0 == 0x8C && p[1] == 0x41)
        return true;

    // 18 (sbb al, [rcx])
    if (b0 == 0x18)
        return true;

    // F3 41 0F 10 (movss xmm0, [r8])
    if (b0 == 0xF3 && p[1] == 0x41 && p[2] == 0x0F && p[3] == 0x10)
        return true;

    // 48 8B 05 (mov rax, [rip+...])
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0x05)
        return true;

    // 4C 89 (mov [r...], r...)
    if (b0 == 0x4C && p[1] == 0x89)
        return true;

    // 48 81 C1 (add rcx, imm32)
    if (b0 == 0x48 && p[1] == 0x81 && p[2] == 0xC1)
        return true;

    // 49 8B 40 (mov rax, [r8+...])
    if (b0 == 0x49 && p[1] == 0x8B && p[2] == 0x40)
        return true;

    // 41 8B (mov eax, [r...])
    if (b0 == 0x41 && p[1] == 0x8B)
        return true;

    // 48 8D 15 (lea rdx, [rip+...])
    if (b0 == 0x48 && p[1] == 0x8D && p[2] == 0x15)
        return true;

    // 48 8D 89 (lea rcx, [rcx+...])
    if (b0 == 0x48 && p[1] == 0x8D && p[2] == 0x89)
        return true;

    // 48 8D 99 (lea rbx, [rcx-...])
    if (b0 == 0x48 && p[1] == 0x8D && p[2] == 0x99)
        return true;

    // 48 8B D9 (mov rbx, rcx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xD9)
        return true;

    // 48 8B FA (mov rdi, rdx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xFA)
        return true;

    // 48 8B D1 (mov rdx, rcx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xD1)
        return true;

    // 48 8B CA (mov rcx, rdx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xCA)
        return true;

    // 48 8B DA (mov rbx, rdx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xDA)
        return true;

    // 48 8B F2 (mov rsi, rdx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xF2)
        return true;

    // 48 8B F1 (mov rsi, rcx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xF1)
        return true;

    // 48 8B F9 (mov rdi, rcx)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xF9)
        return true;

    // 48 8B F8 (mov rdi, rax)
    if (b0 == 0x48 && p[1] == 0x8B && p[2] == 0xF8)
        return true;

    // 48 8D 0D (lea rcx, [rip+...])
    if (b0 == 0x48 && p[1] == 0x8D && p[2] == 0x0D)
        return true;

    // 48 8D 15 (lea rdx, [rip+...])
    if (b0 == 0x48 && p[1] == 0x8D && p[2] == 0x15)
        return true;

    return false;
}

// ── Main ─────────────────────────────────────────────────────────────────

struct FoundFunc {
    DWORD rva;
    BYTE  bytes[32];
    int   len;       // bytes captured (16 or more)
    int   regionIdx;
    char  regionLabel[32];
};

int main() {
    printf("[SCAN2] DayZ Function Prologue Scanner — Batch 2\n");
    printf("[SCAN2] Scanning %d unexplored regions...\n", (int)(sizeof(g_regions) / sizeof(g_regions[0])));

    // Find DayZ process
    DWORD pid = 0;
    if (!GetProcessId("DayZ_x64.exe", &pid) || !pid) {
        printf("[SCAN2] ERROR: DayZ_x64.exe is not running.\n");
        return 1;
    }
    printf("[SCAN2] Found DayZ_x64.exe pid=%lu\n", pid);

    // Get module base
    UINT64 modBase = 0;
    SIZE_T modSize = 0;
    if (!GetModuleInfo(pid, "DayZ_x64.exe", &modBase, &modSize)) {
        printf("[SCAN2] ERROR: Could not get module info.\n");
        return 1;
    }
    printf("[SCAN2] Module base=0x%llX size=0x%zX\n", modBase, modSize);

    // Load the module into our process for reading
    char exePath[MAX_PATH] = {};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("[SCAN2] ERROR: OpenProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    // Get full path
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me{}; me.dwSize = sizeof(me);
            if (Module32First(hSnap, &me)) {
                do {
                    if (!_stricmp(me.szModule, "DayZ_x64.exe")) {
                        strncpy_s(exePath, MAX_PATH, me.szExePath, MAX_PATH - 1);
                        break;
                    }
                } while (Module32Next(hSnap, &me));
            }
            CloseHandle(hSnap);
        }
    }
    CloseHandle(hProc);

    if (!exePath[0]) {
        printf("[SCAN2] ERROR: Could not get exe path.\n");
        return 1;
    }
    printf("[SCAN2] Exe path: %s\n", exePath);

    // LoadLibraryA to get a readable copy
    HMODULE hMod = LoadLibraryA(exePath);
    if (!hMod) {
        printf("[SCAN2] ERROR: LoadLibraryA failed (%lu)\n", GetLastError());
        return 1;
    }

    BYTE* image = (BYTE*)hMod;
    printf("[SCAN2] Loaded image at 0x%p\n", image);

    // Find .text section
    SectionInfo text{};
    if (!FindSection(image, ".text", &text)) {
        printf("[SCAN2] ERROR: .text section not found.\n");
        FreeLibrary(hMod);
        return 1;
    }
    printf("[SCAN2] .text: RVA=0x%llX VSize=0x%zX RawSize=0x%zX\n",
           text.rva, text.virtualSize, text.rawSize);

    BYTE* textBase = text.rawData;
    SIZE_T textSize = text.rawSize;

    // Scan each region
    std::vector<FoundFunc> allFound;

    for (int ri = 0; ri < (int)(sizeof(g_regions) / sizeof(g_regions[0])); ++ri) {
        const Region& reg = g_regions[ri];
        DWORD regStart = reg.startRVA;
        DWORD regEnd   = reg.endRVA;

        // Clamp to .text bounds
        if (regStart < (DWORD)text.rva) regStart = (DWORD)text.rva;
        if (regEnd > (DWORD)(text.rva + textSize)) regEnd = (DWORD)(text.rva + textSize);
        if (regStart >= regEnd) {
            printf("[SCAN2] Region '%s' (0x%X-0x%X) outside .text, skipping.\n", reg.label, reg.startRVA, reg.endRVA);
            continue;
        }

        printf("\n[SCAN2] === Region: %s (0x%06X - 0x%06X) ===\n", reg.label, regStart, regEnd);

        BYTE* regionBase = image + regStart;
        SIZE_T regionSize = regEnd - regStart;

        int regionHits = 0;

        // Scan for CC CC CC CC followed by a prologue
        for (SIZE_T off = 0; off + 20 <= regionSize; ++off) {
            BYTE* p = regionBase + off;

            // Look for int3 padding: CC CC CC CC
            if (p[0] != 0xCC || p[1] != 0xCC || p[2] != 0xCC || p[3] != 0xCC)
                continue;

            // Prologue starts after the int3 padding
            BYTE* prologue = p + 4;

            // Skip additional CC bytes
            int skip = 0;
            while (off + 4 + skip < regionSize && prologue[skip] == 0xCC)
                ++skip;
            prologue += skip;

            // Make sure we have at least 32 bytes to read
            if ((SIZE_T)(prologue - regionBase) + 32 > regionSize)
                continue;

            // Check if this looks like a prologue
            if (!IsPrologueStart(prologue))
                continue;

            DWORD funcRVA = (DWORD)(prologue - image);

            // Read 32 bytes for longer patterns
            BYTE bytes32[32];
            memcpy(bytes32, prologue, 32);

            // Check uniqueness of 16-byte prologue in .text
            if (!IsUniqueInText(textBase, textSize, bytes32, 16, prologue)) {
                // Try 24 bytes
                if (!IsUniqueInText(textBase, textSize, bytes32, 24, prologue)) {
                    // Try 32 bytes
                    if (!IsUniqueInText(textBase, textSize, bytes32, 32, prologue)) {
                        continue;  // Not unique even at 32 bytes, skip
                    }
                }
            }

            // Determine minimum unique length
            int minLen = 16;
            if (!IsUniqueInText(textBase, textSize, bytes32, 16, prologue)) {
                minLen = 24;
                if (!IsUniqueInText(textBase, textSize, bytes32, 24, prologue)) {
                    minLen = 32;
                }
            }

            FoundFunc ff{};
            ff.rva = funcRVA;
            ff.len = minLen;
            ff.regionIdx = ri;
            strncpy_s(ff.regionLabel, sizeof(ff.regionLabel), reg.label, _TRUNCATE);
            memcpy(ff.bytes, prologue, minLen);

            allFound.push_back(ff);
            ++regionHits;

            // Print immediately
            printf("[SCAN2]   RVA=0x%06X  len=%d  bytes=", funcRVA, minLen);
            for (int b = 0; b < minLen; ++b)
                printf("\\x%02X", bytes32[b]);
            printf("\n");

            // Skip past this function (at least 16 bytes)
            off = (prologue - regionBase) + 16 - 1;
        }

        printf("[SCAN2]   Found %d unique prologues in %s\n", regionHits, reg.label);
    }

    // Summary
    printf("\n\n[SCAN2] ═══════════════════════════════════════════════════════════════\n");
    printf("[SCAN2] TOTAL unique prologues found: %d\n", (int)allFound.size());
    printf("[SCAN2] ═══════════════════════════════════════════════════════════════\n\n");

    // Output in AUTO_OFFSET format for copy-paste
    printf("[SCAN2] === AUTO_OFFSET entries for Updater.cpp ===\n\n");

    // Group by region
    int currentRegion = -1;
    int funcCount = 0;
    for (auto& ff : allFound) {
        if (ff.regionIdx != currentRegion) {
            currentRegion = ff.regionIdx;
            funcCount = 0;
            printf("\t// === Region: %s (0x%06X-0x%06X) ===\n\n",
                   g_regions[ff.regionIdx].label,
                   g_regions[ff.regionIdx].startRVA,
                   g_regions[ff.regionIdx].endRVA);
        }
        ++funcCount;

        // Build the pattern string
        char patStr[256] = {};
        char maskStr[256] = {};
        int pos = 0, mpos = 0;
        for (int b = 0; b < ff.len; ++b) {
            pos += sprintf_s(patStr + pos, sizeof(patStr) - pos, "\\x%02X", ff.bytes[b]);
            maskStr[mpos++] = 'x';
        }
        maskStr[mpos] = 0;

        printf("\t// ScanTemp2_%s_Func%d — RVA 0x%06X\n", ff.regionLabel, funcCount, ff.rva);
        printf("\tAUTO_OFFSET(Functions, ScanTemp2_%s_Func%d,\n", ff.regionLabel, funcCount);
        printf("\t\t\"%s\",\n", patStr);
        printf("\t\t\"%s\",\n", maskStr);
        printf("\t\t\".text\", ScanType::FuncRVA, 0);\n\n");
    }

    // Also output Offsets.h entries
    printf("\n[SCAN2] === Offsets.h entries ===\n\n");
    for (auto& ff : allFound) {
        // Count per region
        static int regionCounts[64] = {};
        regionCounts[ff.regionIdx]++;
    }

    // Re-iterate for offsets.h
    int prevRegion2 = -1;
    int fc2 = 0;
    for (auto& ff : allFound) {
        if (ff.regionIdx != prevRegion2) {
            prevRegion2 = ff.regionIdx;
            fc2 = 0;
        }
        ++fc2;
        printf("\tADD_OFFSET(Functions, ScanTemp2_%s_Func%d);\t\t\t\t// 0x%06X\n",
               ff.regionLabel, fc2, ff.rva);
    }

    FreeLibrary(hMod);
    printf("\n[SCAN2] Done.\n");
    return 0;
}
