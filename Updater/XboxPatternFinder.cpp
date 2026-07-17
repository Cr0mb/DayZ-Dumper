// XboxPatternFinder.cpp — Find patterns for known offsets on Xbox 1.29
// Build: same as ScanTemp2.cpp
// Run: XboxPatternFinder.exe --xbox
// This scans the live Xbox process for instructions that access known offsets.

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

// Known Xbox 1.29 offsets that we want to find patterns for
struct KnownOffset {
    const char* name;
    DWORD offset;           // The disp32/disp8 we're looking for
    bool is_small;          // true if disp8 (1 byte), false if disp32 (4 bytes)
};

static KnownOffset g_offsets[] = {
    // World offsets - from working External
    { "World::Camera",          0x30,   false },
    { "World::NearEntList",     0x1030, false },
    { "World::FarEntList",      0x1080, false },
    { "World::NearTableSize",   0x1038, false },
    { "World::LocalPlayer",     0x2960, false },
    { "World::LocalPlayer2",    0x2958, false },  // alternate
    // Entity offsets
    { "Entity::VisualState",    0x1C0,  false },
    { "Entity::Type",           0x178,  false },
    { "Entity::NetworkId",      0x6DC,  false },
    // Network offsets
    { "Network::ServerName",    0x308,  false },
    { "Network::Ping",          0x33C,  false },
    { "Network::ScoreboardSize",0x24,   true  },
    { nullptr, 0, false }
};

// Instruction patterns that access struct members:
// mov reg, [reg+disp32]  = 48 8B ?? XX XX XX XX (XX XX XX XX = disp32)
// mov [reg+disp32], reg  = 48 89 ?? XX XX XX XX
// lea reg, [reg+disp32]  = 48 8D ?? XX XX XX XX
// movss xmm, [reg+disp32]= F3 0F 10 ?? XX XX XX XX

static bool MatchDisp32(const BYTE* code, DWORD offset, int* instLen) {
    // Check common 64-bit mov/lea patterns
    // 48 8B 8? DD DD DD DD = mov rcx, [reg+disp32]
    // 48 8B 9? DD DD DD DD = mov rbx, [reg+disp32]
    // etc.

    if (code[0] == 0x48) {
        if ((code[1] == 0x8B || code[1] == 0x89 || code[1] == 0x8D) &&
            (code[2] & 0xC0) == 0x80) {  // mod=10 (disp32)
            DWORD disp = *(DWORD*)(code + 3);
            if (disp == offset) {
                *instLen = 7;
                return true;
            }
        }
        // 48 8B 83 DD DD DD DD = mov rax, [rbx+disp32]
        if ((code[1] == 0x8B || code[1] == 0x89 || code[1] == 0x8D) &&
            (code[2] >= 0x80 && code[2] <= 0xBF)) {
            DWORD disp = *(DWORD*)(code + 3);
            if (disp == offset) {
                *instLen = 7;
                return true;
            }
        }
    }

    // 4C 8B ?? DD DD DD DD = mov r8/r9/etc, [reg+disp32]
    if (code[0] == 0x4C) {
        if ((code[1] == 0x8B || code[1] == 0x89 || code[1] == 0x8D) &&
            (code[2] & 0xC0) == 0x80) {
            DWORD disp = *(DWORD*)(code + 3);
            if (disp == offset) {
                *instLen = 7;
                return true;
            }
        }
    }

    // 49 8D ?? DD DD DD DD = lea reg, [r8/r9+disp32]
    if (code[0] == 0x49) {
        if ((code[1] == 0x8D || code[1] == 0x8B) &&
            (code[2] & 0xC0) == 0x80) {
            DWORD disp = *(DWORD*)(code + 3);
            if (disp == offset) {
                *instLen = 7;
                return true;
            }
        }
    }

    return false;
}

static void PrintPatternContext(BYTE* textBase, SIZE_T hitOffset, SIZE_T textSize, int instLen) {
    // Print 16 bytes before and 16 bytes at match
    int preBytes = 16;
    int postBytes = 16;

    SIZE_T start = (hitOffset >= preBytes) ? (hitOffset - preBytes) : 0;
    SIZE_T end = (hitOffset + postBytes < textSize) ? (hitOffset + postBytes) : textSize;

    printf("    RVA=0x%06llX: ", (unsigned long long)(0x1000 + hitOffset));
    for (SIZE_T i = start; i < hitOffset; ++i) printf("%02X ", textBase[i]);
    printf("| ");
    for (SIZE_T i = hitOffset; i < hitOffset + instLen && i < end; ++i) printf("%02X ", textBase[i]);
    printf("| ");
    for (SIZE_T i = hitOffset + instLen; i < end; ++i) printf("%02X ", textBase[i]);
    printf("\n");
}

int main(int argc, char** argv) {
    printf("=== Xbox Pattern Finder for DayZ 1.29 ===\n\n");

    // For now, we'll use the already-dumped PE from the Dumper
    // Read from dump.log to get the reconstructed image address

    printf("TODO: Connect to NeacSafe driver and scan the live Xbox memory\n");
    printf("This is a stub - implement using NeacSafe64 memory reading\n\n");

    printf("Known offsets to search for:\n");
    for (int i = 0; g_offsets[i].name; ++i) {
        printf("  %-24s = 0x%X\n", g_offsets[i].name, g_offsets[i].offset);
    }

    return 0;
}
