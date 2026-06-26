#include "MemImage.h"
#include "Driver.h"

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace MemImage {

namespace {
    // Cache the last successful reconstruction so SaveLastTo() can dump it.
    PBYTE g_lastImg  = nullptr;
    DWORD g_lastSize = 0;
}

bool SaveLastTo(const char* path) {
    if (!g_lastImg || !g_lastSize) {
        printf("[MEMIMAGE] SaveLastTo: no image held — call DumpLive first.\n");
        return false;
    }
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || !f) {
        printf("[MEMIMAGE] SaveLastTo: open '%s' failed\n", path);
        return false;
    }
    size_t wr = fwrite(g_lastImg, 1, g_lastSize, f);
    fclose(f);
    if (wr != g_lastSize) {
        printf("[MEMIMAGE] SaveLastTo: short write %zu/%u\n", wr, g_lastSize);
        return false;
    }
    printf("[MEMIMAGE] saved %u bytes -> %s\n", g_lastSize, path);
    return true;
}

bool DumpLive(const char* processName, UINT64* outModule, PBYTE* outAllocated) {
    if (!processName || !outModule || !outAllocated) return false;
    *outModule = 0;
    *outAllocated = nullptr;

    if (!driver::ConnectDriver()) {
        printf("[MEMIMAGE] driver::ConnectDriver() failed.\n");
        return false;
    }
    if (!driver::AttachToProcessName(processName)) {
        printf("[MEMIMAGE] AttachToProcessName('%s') failed.\n", processName);
        return false;
    }
    uint64_t base = driver::GetProcessBase();
    if (!base) {
        printf("[MEMIMAGE] driver-reported base is 0.\n");
        return false;
    }

    // ── PE headers ────────────────────────────────────────────────────────
    BYTE headers[0x1000] = {};
    if (!driver::ReadMem(base, headers, sizeof(headers))) {
        printf("[MEMIMAGE] header read failed at 0x%llX\n",
               (unsigned long long)base);
        return false;
    }
    if (headers[0] != 'M' || headers[1] != 'Z') {
        printf("[MEMIMAGE] no MZ at base (got %02X %02X)\n", headers[0], headers[1]);
        return false;
    }
    DWORD e_lfanew = *(DWORD*)(headers + 0x3C);
    if (e_lfanew + 24 + 240 > sizeof(headers)) {
        printf("[MEMIMAGE] PE header past 4 KiB (e_lfanew=0x%X)\n", e_lfanew);
        return false;
    }
    if (memcmp(headers + e_lfanew, "PE\0\0", 4) != 0) {
        printf("[MEMIMAGE] bad PE signature at +0x%X\n", e_lfanew);
        return false;
    }
    WORD  nSections     = *(WORD*) (headers + e_lfanew + 6);
    WORD  sizeOptHdr    = *(WORD*) (headers + e_lfanew + 20);
    WORD  optMagic      = *(WORD*) (headers + e_lfanew + 24);
    DWORD sizeOfImage   = *(DWORD*)(headers + e_lfanew + 24 + 56);
    DWORD sizeOfHeaders = *(DWORD*)(headers + e_lfanew + 24 + 60);

    printf("[MEMIMAGE] PE magic=0x%X sections=%u SizeOfImage=0x%X SizeOfHeaders=0x%X\n",
           optMagic, nSections, sizeOfImage, sizeOfHeaders);
    if (optMagic != 0x20B) {
        printf("[MEMIMAGE] not PE32+ (magic 0x%X)\n", optMagic);
        return false;
    }
    if (sizeOfImage == 0 || sizeOfImage > 0x40000000) {
        printf("[MEMIMAGE] implausible SizeOfImage 0x%X\n", sizeOfImage);
        return false;
    }

    // ── Allocate flat memory image + pull every section by RVA ───────────
    PBYTE img = (PBYTE)VirtualAlloc(nullptr, sizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!img) {
        printf("[MEMIMAGE] VirtualAlloc(0x%X) failed err=%lu\n",
               sizeOfImage, GetLastError());
        return false;
    }
    memcpy(img, headers, (sizeOfHeaders < sizeof(headers)) ? sizeOfHeaders : sizeof(headers));
    if (sizeOfHeaders > sizeof(headers)) {
        if (!driver::ReadMem(base, img, sizeOfHeaders)) {
            printf("[MEMIMAGE] full header read failed (size 0x%X)\n", sizeOfHeaders);
            VirtualFree(img, 0, MEM_RELEASE);
            return false;
        }
    }

    DWORD firstSecOff = e_lfanew + 24 + sizeOptHdr;
    DWORD total = 0, full = 0, partial = 0, empty = 0;
    for (WORD i = 0; i < nSections; ++i) {
        DWORD off  = firstSecOff + i * 40;
        char name[9] = {};
        memcpy(name, img + off, 8);
        DWORD vsize = *(DWORD*)(img + off + 8);
        DWORD vaddr = *(DWORD*)(img + off + 12);
        DWORD rsize = *(DWORD*)(img + off + 16);
        DWORD map_size = vsize ? vsize : rsize;
        if (vaddr + map_size > sizeOfImage) {
            map_size = sizeOfImage - vaddr;
        }
        // Page-by-page read tolerates cold (un-faulted-in) pages — they get
        // zero-filled rather than aborting the whole dump.
        DWORD got = 0;
        for (DWORD pos = 0; pos < map_size; pos += 0x1000) {
            DWORD want = (map_size - pos) > 0x1000 ? 0x1000 : (map_size - pos);
            if (driver::ReadMem(base + vaddr + pos, img + vaddr + pos, want)) {
                got += want;
            }
        }
        // Memory-image layout: PointerToRawData == VirtualAddress.
        *(DWORD*)(img + off + 16) = map_size;
        *(DWORD*)(img + off + 20) = vaddr;
        ++total;
        if (got == map_size && got > 0) ++full;
        else if (got > 0) ++partial;
        else ++empty;
        printf("[MEMIMAGE]   section %-8s vaddr=0x%08X size=0x%08X read=0x%08X\n",
               name, vaddr, map_size, got);
    }
    *(DWORD*)(img + e_lfanew + 24 + 32) = 0x1000;
    *(DWORD*)(img + e_lfanew + 24 + 36) = 0x1000;
    printf("[MEMIMAGE] reconstructed (%u sections: %u full, %u partial, %u empty)\n",
           total, full, partial, empty);

    *outModule    = (UINT64)img;
    *outAllocated = img;
    g_lastImg  = img;
    g_lastSize = sizeOfImage;
    return true;
}

} // namespace MemImage
