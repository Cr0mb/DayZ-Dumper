// ScanTemp3.cpp — Scan 19 narrow gap regions in DayZ_x64.exe .text for unique function prologues
// Compile: cl /std:c++17 /O2 /EHsc /Fe"ScanTemp3.exe" ScanTemp3.cpp /link /SUBSYSTEM:CONSOLE

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <set>
#include <string>
#include <algorithm>
#include <map>

struct Region {
    uint32_t start;
    uint32_t end;
    const char* label;
};

static Region regions[] = {
    { 0x001000, 0x003000, "CRT_Startup" },
    { 0x030000, 0x042000, "Gap_Before_Early" },
    { 0x043000, 0x0AB000, "Gap_Early_Network" },
    { 0x100000, 0x10F000, "Gap_100k" },
    { 0x110000, 0x140000, "Gap_110k" },
    { 0x210000, 0x280000, "Large_Gap_210k" },
    { 0x280000, 0x300000, "Gap_280k" },
    { 0x330000, 0x354000, "Gap_330k" },
    { 0x380000, 0x3D0000, "Gap_380k" },
    { 0x400000, 0x420000, "Gap_400k" },
    { 0x460000, 0x4A0000, "Gap_460k" },
    { 0x4C0000, 0x500000, "Gap_4C0k" },
    { 0x580000, 0x5C0000, "Gap_580k" },
    { 0x600000, 0x6C0000, "Gap_600k" },
    { 0x730000, 0x735000, "Gap_730k" },
    { 0x780000, 0x7B0000, "Gap_780k" },
    { 0x800000, 0x8A0000, "Gap_800k" },
    { 0x900000, 0x920000, "Gap_900k" },
    { 0x9B0000, 0xA00000, "Gap_9B0k" },
};

// Known prologue first bytes (after CC padding) — common x64 function starts
static bool isPrologueStart(uint8_t b) {
    switch (b) {
    case 0x40: case 0x48: case 0x4C: // REX prefixes
    case 0x53: case 0x55: case 0x56: case 0x57: // push rbx/rbp/rsi/rdi
    case 0x83: case 0x8B: // various ops
    case 0x0F: // two-byte opcodes
    case 0xE8: case 0xE9: // call/jmp (thunks)
    case 0xC3: // ret (trivial funcs)
    case 0xC6: case 0xC7: // mov byte/word
    case 0xF3: case 0xF2: // REP prefixes (SSE)
    case 0x66: // operand size prefix
    case 0x51: case 0x52: case 0x50: // push rcx/rdx/rax
    case 0x41: // REX.B prefix
    case 0x33: // xor reg,reg
    case 0x3B: // cmp
    case 0x80: // cmp byte
    case 0x85: // test
    case 0x89: // mov r/m, reg
    case 0x8A: // mov reg, r/m
    case 0xB8: case 0xB9: // mov eax/ecx, imm32
    case 0x44: // REX.R prefix
    case 0x45: // REX.RB prefix
        return true;
    default:
        return false;
    }
}

// Check if 16 bytes contain at least some non-CC, non-zero diversity
static bool isInterestingPattern(const uint8_t* p) {
    // Must not be all same byte
    int unique = 0;
    uint8_t seen[256] = {};
    for (int i = 0; i < 16; i++) {
        if (!seen[p[i]]) { seen[p[i]] = 1; unique++; }
    }
    return unique >= 4; // at least 4 distinct byte values
}

struct FoundFunc {
    uint32_t rva;
    uint8_t bytes[16];
    std::string region;
};

int main() {
    const char* exePath = "D:\\SteamLibrary\\steamapps\\common\\DayZ\\DayZ_x64.exe";
    
    HMODULE hMod = LoadLibraryA(exePath);
    if (!hMod) {
        printf("ERROR: LoadLibraryA failed (%lu)\n", GetLastError());
        return 1;
    }
    
    uint8_t* base = (uint8_t*)hMod;
    
    // Parse PE headers to find .text section
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto sections = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    
    uint8_t* textBase = nullptr;
    uint32_t textSize = 0;
    
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            textBase = base + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
            printf("[INFO] .text section: VA=0x%08X size=0x%08X\n", 
                   sections[i].VirtualAddress, textSize);
            break;
        }
    }
    
    if (!textBase) {
        printf("ERROR: .text section not found\n");
        FreeLibrary(hMod);
        return 1;
    }
    
    // Track unique 16-byte patterns globally
    std::set<std::string> seenPatterns;
    std::vector<FoundFunc> allFound;
    int totalCount = 0;
    
    for (auto& reg : regions) {
        // Clamp region to .text bounds
        uint32_t scanStart = reg.start;
        uint32_t scanEnd = reg.end;
        
        if (scanStart >= textSize || scanEnd > textSize) {
            // Region partially or fully outside .text
            if (scanStart >= textSize) {
                printf("[SKIP] Region %s (0x%06X-0x%06X) outside .text\n", reg.label, reg.start, reg.end);
                continue;
            }
            scanEnd = textSize;
        }
        
        printf("\n[SCAN] Region: %s (0x%06X - 0x%06X)\n", reg.label, scanStart, scanEnd);
        
        int regionHits = 0;
        
        for (uint32_t off = scanStart; off + 20 < scanEnd; off++) {
            // Look for CC CC CC CC (4+ int3 padding bytes)
            if (textBase[off] != 0xCC || textBase[off+1] != 0xCC || 
                textBase[off+2] != 0xCC || textBase[off+3] != 0xCC)
                continue;
            
            // Find where the CC padding ends
            uint32_t funcStart = off + 4;
            while (funcStart < scanEnd && textBase[funcStart] == 0xCC)
                funcStart++;
            
            if (funcStart >= scanEnd) continue;
            
            uint8_t firstByte = textBase[funcStart];
            if (!isPrologueStart(firstByte)) continue;
            
            // Read 16 bytes from function start
            if (funcStart + 16 > scanEnd) continue;
            
            uint8_t pattern[16];
            memcpy(pattern, &textBase[funcStart], 16);
            
            if (!isInterestingPattern(pattern)) continue;
            
            // Check uniqueness
            std::string key((char*)pattern, 16);
            if (seenPatterns.count(key)) continue;
            seenPatterns.insert(key);
            
            uint32_t rva = funcStart; // Since loaded at image base, offset = RVA
            // Actually RVA = offset from module base in memory
            // hMod is loaded at some base, but the file mapping means offsets match RVAs
            
            FoundFunc f;
            f.rva = rva;
            memcpy(f.bytes, pattern, 16);
            f.region = reg.label;
            allFound.push_back(f);
            regionHits++;
            totalCount++;
        }
        
        printf("  -> %d unique prologues found in %s\n", regionHits, reg.label);
    }
    
    printf("\n========================================\n");
    printf("TOTAL UNIQUE PROLOGUES: %d\n", totalCount);
    printf("========================================\n\n");
    
    // Print results grouped by region
    std::string currentRegion;
    int funcIdx = 0;
    for (auto& f : allFound) {
        if (f.region != currentRegion) {
            currentRegion = f.region;
            printf("\n// === Region: %s ===\n", currentRegion.c_str());
            funcIdx = 0;
        }
        funcIdx++;
        printf("// RVA 0x%06X\n", f.rva);
        printf("AUTO_OFFSET(Functions, Gap3_%s_Func%d,\n", f.region.c_str(), funcIdx);
        printf("    \"");
        for (int i = 0; i < 16; i++) {
            printf("\\x%02X", f.bytes[i]);
        }
        printf("\",\n    \"xxxxxxxxxxxxxxxx\",\n    \".text\", ScanType::FuncRVA, 0);\n\n");
    }
    
    // Also print a summary table
    printf("\n========================================\n");
    printf("SUMMARY TABLE\n");
    printf("========================================\n");
    printf("%-8s  %-24s  %s\n", "RVA", "Region", "First 16 bytes");
    printf("--------  ------------------------  --------------------------------\n");
    for (auto& f : allFound) {
        printf("0x%06X  %-24s  ", f.rva, f.region.c_str());
        for (int i = 0; i < 16; i++) printf("%02X ", f.bytes[i]);
        printf("\n");
    }
    
    FreeLibrary(hMod);
    return 0;
}
