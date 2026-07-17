// XboxIdentityDumper.cpp — Dump Xbox PlayerIdentity structures from live DayZ process
// This tool reads the NetworkClient scoreboard table and dumps all identity records
// to help reverse engineer the Xbox gamertag storage layout.
//
// Build:
//   cd /d "D:\GHax Labs\GHaxLabs\DayZ\Dumper"
//   call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
//   cl /std:c++17 /O2 /EHsc /Fe"x64\Release\XboxIdentityDumper.exe" ^
//      "Updater\XboxIdentityDumper.cpp" "Updater\NeacSafe\Driver.cpp" ^
//      /I"Updater" /I"Updater\NeacSafe" /link /SUBSYSTEM:CONSOLE
//
// Run (requires DayZ Xbox running and connected to a server):
//   XboxIdentityDumper.exe

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

// Forward declarations for NeacSafe driver
namespace NeacSafe {
    bool LoadDriver();
    bool AttachProcess(DWORD pid, uint64_t* base);
    bool ReadMemory(uint64_t addr, void* buf, size_t size);
    void UnloadDriver();
}

// Known Xbox 1.29 offsets from Dumper output
#define OFF_WORLD               0x4272168   // Xbox Modbase::World
#define OFF_NETWORK_MANAGER     0x101DEF0   // Xbox Modbase::NetworkManager
#define OFF_NETWORK_CLIENT      0x50        // NetworkManager -> NetworkClient
#define OFF_SCOREBOARD_TABLE    0x18        // NetworkClient -> IdentityTable
#define OFF_SCOREBOARD_SIZE     0x24        // NetworkClient -> IdentityCount
#define OFF_IDENTITY_SIZE       0x170       // Size of each identity record

static uint64_t g_moduleBase = 0;
static DWORD g_pid = 0;

template<typename T>
T ReadMem(uint64_t addr) {
    T val{};
    NeacSafe::ReadMemory(addr, &val, sizeof(T));
    return val;
}

bool ReadString(uint64_t addr, char* buf, size_t maxLen) {
    return NeacSafe::ReadMemory(addr, buf, maxLen);
}

// Read Enfusion string (ptr -> {ptr to data, len, ...})
std::string ReadArmaString(uint64_t ptr) {
    if (!ptr) return "";
    char buf[256] = {0};
    if (!ReadString(ptr, buf, 255)) return "";
    buf[255] = 0;
    // Check if it's a valid ASCII string
    for (int i = 0; i < 255 && buf[i]; ++i) {
        if ((unsigned char)buf[i] < 32 || (unsigned char)buf[i] > 126) {
            buf[i] = 0;
            break;
        }
    }
    return std::string(buf);
}

bool GetProcessId(const char* name, DWORD* pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (!_stricmp(pe.szExeFile, name)) {
                *pid = pe.th32ProcessID;
                CloseHandle(snap);
                return true;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return false;
}

void DumpHex(uint64_t addr, size_t len, const char* label) {
    printf("\n=== %s (0x%llX, %zu bytes) ===\n", label, (unsigned long long)addr, len);
    std::vector<uint8_t> buf(len);
    if (!NeacSafe::ReadMemory(addr, buf.data(), len)) {
        printf("  [READ FAILED]\n");
        return;
    }
    for (size_t i = 0; i < len; i += 16) {
        printf("  +%04zX: ", i);
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            printf("%02X ", buf[i + j]);
        }
        printf(" | ");
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            char c = buf[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
}

void ProbeIdentityStrings(uint64_t ident) {
    printf("\n  String probing at identity 0x%llX:\n", (unsigned long long)ident);

    // Probe every 8-byte aligned offset for potential string pointers
    for (int off = 0; off < 0x180; off += 8) {
        uint64_t ptr = ReadMem<uint64_t>(ident + off);
        if (ptr == 0 || ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;

        char buf[64] = {0};
        if (!ReadString(ptr, buf, 63)) continue;
        buf[63] = 0;

        // Check if it looks like a valid string
        bool valid = true;
        int len = 0;
        for (int i = 0; i < 63 && buf[i]; ++i) {
            if ((unsigned char)buf[i] < 32 || (unsigned char)buf[i] > 126) {
                valid = false;
                break;
            }
            len++;
        }

        if (valid && len >= 2 && len <= 50) {
            printf("    +0x%03X -> 0x%llX = \"%s\" (len=%d)\n",
                off, (unsigned long long)ptr, buf, len);
        }
    }
}

int main() {
    printf("=== Xbox Identity Dumper for DayZ 1.29 ===\n\n");

    if (!GetProcessId("DayZ_x64.exe", &g_pid)) {
        printf("ERROR: DayZ_x64.exe not running\n");
        return 1;
    }
    printf("Found DayZ_x64.exe (PID=%lu)\n", g_pid);

    printf("Loading NeacSafe64 driver...\n");
    if (!NeacSafe::LoadDriver()) {
        printf("ERROR: Failed to load driver\n");
        return 1;
    }

    if (!NeacSafe::AttachProcess(g_pid, &g_moduleBase)) {
        printf("ERROR: Failed to attach to process\n");
        NeacSafe::UnloadDriver();
        return 1;
    }
    printf("Attached: moduleBase=0x%llX\n\n", (unsigned long long)g_moduleBase);

    // Read World pointer
    uint64_t worldPtr = ReadMem<uint64_t>(g_moduleBase + OFF_WORLD);
    printf("World pointer: 0x%llX\n", (unsigned long long)worldPtr);
    if (!worldPtr) {
        printf("ERROR: World pointer is NULL (not in-game?)\n");
        NeacSafe::UnloadDriver();
        return 1;
    }

    // Read NetworkManager
    uint64_t netMgr = ReadMem<uint64_t>(g_moduleBase + OFF_NETWORK_MANAGER);
    printf("NetworkManager: 0x%llX\n", (unsigned long long)netMgr);
    if (!netMgr) {
        printf("ERROR: NetworkManager is NULL\n");
        NeacSafe::UnloadDriver();
        return 1;
    }

    // Read NetworkClient
    uint64_t netClient = ReadMem<uint64_t>(netMgr + OFF_NETWORK_CLIENT);
    printf("NetworkClient: 0x%llX\n", (unsigned long long)netClient);
    if (!netClient) {
        printf("ERROR: NetworkClient is NULL (not connected to server?)\n");
        NeacSafe::UnloadDriver();
        return 1;
    }

    // Dump NetworkClient structure
    DumpHex(netClient, 0x100, "NetworkClient");

    // Read scoreboard table
    uint64_t table = ReadMem<uint64_t>(netClient + OFF_SCOREBOARD_TABLE);
    uint32_t count = ReadMem<uint32_t>(netClient + OFF_SCOREBOARD_SIZE);
    printf("\nScoreboard: table=0x%llX count=%u\n", (unsigned long long)table, count);

    if (!table || count == 0 || count > 100) {
        printf("WARNING: Scoreboard appears empty or invalid\n");
    } else {
        printf("\n=== Identity Records ===\n");
        for (uint32_t i = 0; i < count && i < 10; ++i) {
            uint64_t ident = ReadMem<uint64_t>(table + i * 8);
            printf("\n--- Identity[%u] @ 0x%llX ---\n", i, (unsigned long long)ident);

            if (!ident) {
                printf("  [NULL]\n");
                continue;
            }

            // Dump raw identity record
            DumpHex(ident, OFF_IDENTITY_SIZE, "IdentityRecord");

            // Probe for strings at various offsets
            ProbeIdentityStrings(ident);

            // Read known offsets
            uint64_t netID = ReadMem<uint64_t>(ident + 0x30);  // OFF_Network_Table_ID
            printf("\n  NetworkID (+0x30): %llu\n", (unsigned long long)netID);

            // Try Steam offsets
            uint64_t namePtr = ReadMem<uint64_t>(ident + 0xF8);  // Steam PlayerName
            uint64_t steamPtr = ReadMem<uint64_t>(ident + 0xA0); // Steam SteamID

            std::string name = ReadArmaString(namePtr);
            std::string steam = ReadArmaString(steamPtr);

            printf("  PlayerName (+0xF8): ptr=0x%llX str='%s'\n",
                (unsigned long long)namePtr, name.c_str());
            printf("  SteamID (+0xA0): ptr=0x%llX str='%s'\n",
                (unsigned long long)steamPtr, steam.c_str());
        }
    }

    printf("\n=== Done ===\n");
    NeacSafe::UnloadDriver();
    return 0;
}

// Stub implementations - these would be linked from the actual NeacSafe driver code
namespace NeacSafe {
    // These are placeholders - the real implementation is in Driver.cpp
    static HANDLE g_device = INVALID_HANDLE_VALUE;
    static uint64_t g_base = 0;

    bool LoadDriver() {
        // Implementation would load the NeacSafe64 driver
        printf("  [Note: Using existing driver from Updater session]\n");
        return true;
    }

    bool AttachProcess(DWORD pid, uint64_t* base) {
        // Implementation would attach to the process
        *base = 0;  // Would be filled by driver
        return false;  // Stub returns false
    }

    bool ReadMemory(uint64_t addr, void* buf, size_t size) {
        return false;  // Stub
    }

    void UnloadDriver() {
        // Cleanup
    }
}
