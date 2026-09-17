// PatternFinder130.cpp — Find patterns for 1.30 Experimental offsets
// Build: cl /std:c++17 /O2 /EHsc PatternFinder130.cpp /link /SUBSYSTEM:CONSOLE

#include <Windows.h>
#include <cstdio>
#include <cstring>

struct SectionInfo { UINT64 rva; SIZE_T size; };

static bool FindTextSection(BYTE* img, SectionInfo* out) {
    auto dos = (IMAGE_DOS_HEADER*)img;
    auto nt  = (IMAGE_NT_HEADERS*)(img + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)sec[i].Name, ".text", 5) == 0) {
            out->rva  = sec[i].VirtualAddress;
            out->size = sec[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// Search for mov reg, [reg+offset] patterns (disp32)
static void FindOffsetAccess32(BYTE* text, SIZE_T textSize, UINT64 textRva,
                                int offset, const char* name, int maxResults = 5) {
    printf("\n=== %s (disp32 = 0x%X) ===\n", name, offset);
    int found = 0;

    for (SIZE_T i = 0; i < textSize - 16 && found < maxResults; ++i) {
        BYTE* p = text + i;

        // 48 8B xx disp32 — mov r64, [r64+disp32]
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8B) {
            int modrm = p[2];
            int mod = (modrm >> 6) & 3;
            if (mod == 2) {
                int disp = *(int*)(p + 3);
                if (disp == offset) {
                    UINT64 rva = textRva + i;
                    printf("[0x%06llX] ", rva);
                    for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                    printf("\n");
                    found++;
                }
            }
        }

        // 48 89 xx disp32 — mov [r64+disp32], r64
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x89) {
            int modrm = p[2];
            int mod = (modrm >> 6) & 3;
            if (mod == 2) {
                int disp = *(int*)(p + 3);
                if (disp == offset) {
                    UINT64 rva = textRva + i;
                    printf("[0x%06llX] ", rva);
                    for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                    printf("\n");
                    found++;
                }
            }
        }

        // 48 8D xx disp32 — lea r64, [r64+disp32]
        if (p[0] == 0x48 && p[1] == 0x8D) {
            int modrm = p[2];
            int mod = (modrm >> 6) & 3;
            if (mod == 2) {
                int disp = *(int*)(p + 3);
                if (disp == offset) {
                    UINT64 rva = textRva + i;
                    printf("[0x%06llX] lea: ", rva);
                    for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                    printf("\n");
                    found++;
                }
            }
        }
    }

    if (found == 0) printf("  (none found)\n");
}

// Search for disp8 memory access (offset fits in signed byte: -128 to 127)
static void FindOffsetAccessDisp8(BYTE* text, SIZE_T textSize, UINT64 textRva,
                                   int offset, const char* name, int maxResults = 5) {
    printf("\n=== %s (disp8 = 0x%X) ===\n", name, offset);
    int found = 0;

    for (SIZE_T i = 0; i < textSize - 16 && found < maxResults; ++i) {
        BYTE* p = text + i;

        // REX.W + 8B modrm disp8 — mov r64, [r64+disp8]
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8B) {
            int modrm = p[2];
            int mod = (modrm >> 6) & 3;
            if (mod == 1) {  // disp8
                int disp = (signed char)p[3];
                if (disp == offset) {
                    UINT64 rva = textRva + i;
                    printf("[0x%06llX] mov: ", rva);
                    for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                    printf("\n");
                    found++;
                }
            }
        }

        // REX.W + 89 modrm disp8 — mov [r64+disp8], r64
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x89) {
            int modrm = p[2];
            int mod = (modrm >> 6) & 3;
            if (mod == 1) {
                int disp = (signed char)p[3];
                if (disp == offset) {
                    UINT64 rva = textRva + i;
                    printf("[0x%06llX] mov: ", rva);
                    for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                    printf("\n");
                    found++;
                }
            }
        }

        // F3 0F 10/11 modrm disp8 — movss xmm, [r64+disp8]
        if (p[0] == 0xF3 && p[1] == 0x0F && (p[2] == 0x10 || p[2] == 0x11)) {
            int modrm = p[3];
            int mod = (modrm >> 6) & 3;
            if (mod == 1) {
                int disp = (signed char)p[4];
                if (disp == offset) {
                    UINT64 rva = textRva + i;
                    printf("[0x%06llX] movss: ", rva);
                    for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                    printf("\n");
                    found++;
                }
            }
        }

        // C6 40 xx yy — mov byte [rax+disp8], imm8
        if (p[0] == 0xC6 && (p[1] & 0xC7) == 0x40) {
            int disp = (signed char)p[2];
            if (disp == offset) {
                UINT64 rva = textRva + i;
                printf("[0x%06llX] movb: ", rva);
                for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                printf("\n");
                found++;
            }
        }

        // 80 78 xx yy — cmp byte [rax+disp8], imm8
        if (p[0] == 0x80 && (p[1] & 0xC7) == 0x78) {
            int disp = (signed char)p[2];
            if (disp == offset) {
                UINT64 rva = textRva + i;
                printf("[0x%06llX] cmpb: ", rva);
                for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                printf("\n");
                found++;
            }
        }

        // 8A modrm disp8 — mov r8, [r64+disp8]
        if (p[0] == 0x8A || (p[0] >= 0x40 && p[0] <= 0x4F && p[1] == 0x8A)) {
            int off = (p[0] == 0x8A) ? 1 : 2;
            int modrm = p[off];
            int mod = (modrm >> 6) & 3;
            if (mod == 1) {
                int disp = (signed char)p[off+1];
                if (disp == offset) {
                    UINT64 rva = textRva + i;
                    printf("[0x%06llX] movb: ", rva);
                    for (int j = 0; j < 16; j++) printf("%02X ", p[j]);
                    printf("\n");
                    found++;
                }
            }
        }
    }

    if (found == 0) printf("  (none found)\n");
}

int main(int argc, char** argv) {
    printf("=== DayZ 1.30 Experimental Pattern Finder ===\n\n");

    const char* defaultPath = "D:\\SteamLibrary\\steamapps\\common\\DayZ Exp\\DayZ_x64.exe";
    const char* exePath = (argc > 1) ? argv[1] : defaultPath;

    if (GetFileAttributesA(exePath) == INVALID_FILE_ATTRIBUTES) {
        // Try alternate path
        exePath = "D:\\SteamLibrary\\steamapps\\common\\DayZ\\DayZ_x64.exe";
    }

    printf("Loading: %s\n", exePath);
    HMODULE hMod = LoadLibraryExA(exePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) {
        printf("ERROR: LoadLibraryExA failed (%lu)\n", GetLastError());
        return 1;
    }

    BYTE* img = (BYTE*)hMod;
    SectionInfo textSec;
    if (!FindTextSection(img, &textSec)) {
        printf("ERROR: .text section not found\n");
        FreeLibrary(hMod);
        return 1;
    }
    printf(".text: RVA 0x%llX, size 0x%llX\n", textSec.rva, textSec.size);

    BYTE* textBase = img + textSec.rva;

    printf("\n============ CRITICAL OFFSET SEARCHES ============\n");

    // Entity struct offsets
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x180, "Entity::Type");
    FindOffsetAccessDisp8(textBase, textSec.size, textSec.rva, 0xE2, "Entity::IsDead(disp8)");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x684, "Entity::NetworkId");

    // DayZPlayer offsets
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x7E0, "DayZPlayer::Skeleton");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x650, "DayZPlayer::Inventory");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x670, "DayZInfected::Skeleton");

    // Animation offsets
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0xBE8, "Animation::MatrixArray");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x118, "Animation::AnimationComp");
    FindOffsetAccessDisp8(textBase, textSec.size, textSec.rva, 0x54, "Animation::MatrixB(disp8)");

    // Camera offsets - disp8 range
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x1B8, "Camera::Base");
    FindOffsetAccessDisp8(textBase, textSec.size, textSec.rva, 0x4, "Camera::ViewMatrix(disp8)", 10);
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0xD0, "Camera::ProjectionD1(disp32)");
    FindOffsetAccessDisp8(textBase, textSec.size, textSec.rva, 0x7C, "Camera::ProjectionD2(disp8)");

    // World offsets
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0xF70, "World::NearEntList");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x10B8, "World::FarEntList");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x2010, "World::SlowEntList");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x2078, "World::BulletList");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x2960, "World::LocalPlayer");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0xC00, "World::Grass");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0xB70, "World::ItemList");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x2970, "World::TimeScale");

    // Entity VisualState
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x158, "Entity::VisualState");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x120, "Entity::FutureVisualState");

    // Ammo offsets (need to verify which changed)
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x90, "Ammo::AirFriction");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x3C0, "Ammo::Caliber");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x3CC, "Ammo::Dispersion");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x38C, "AmmoType::InitSpeed");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x398, "AmmoType::AirFriction");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x3A8, "AmmoType::CoefGravity");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x44, "Magazine::Count");

    // Skeleton
    FindOffsetAccessDisp8(textBase, textSec.size, textSec.rva, 0x90, "Skeleton::AnimClass2(disp8)");

    // Inventory offsets
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x138, "Inventory::Hands");
    FindOffsetAccess32(textBase, textSec.size, textSec.rva, 0x178, "Inventory::NestedCargo");

    FreeLibrary(hMod);
    printf("\n=== Done ===\n");
    return 0;
}
