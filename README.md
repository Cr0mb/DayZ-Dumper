# DayZ-Dumper v5

**Live-memory PE signature scanner for DayZ 1.29/1.30**

Steam + Microsoft Store / Game Pass + Experimental | 305 Offsets

---

## Overview

DayZ-Dumper is a one-shot offset extractor. Run `Updater.exe` and it pattern-scans the running `DayZ_x64.exe` for **305 known signatures**, prints the resolved RVAs / struct offsets, and writes a `dump.log` next to the executable.

**Multi-platform out of the box** — it works against Steam, Microsoft Store / Xbox Game Pass, and **1.30 Experimental** builds. Experimental builds are auto-detected via the "DayZ Exp" window title.

The Game Pass image cannot be opened from user mode at all (Microsoft's per-file licensing filter denies every read, including elevated `robocopy /B`). To get around this, the dumper drives a **NeacSafe64** minifilter driver — its kernel-side R/W primitive bypasses `clipsp` and BattlEye's `ObRegisterCallbacks` handle-stripping in the same stroke. The full decrypted PE gets reconstructed in dumper memory, then pattern-scanned with the existing Steam sig table.

**Single-file, self-contained.** The driver is embedded as an `RCDATA` resource inside `Updater.exe` and extracted to `%LOCALAPPDATA%\GHax Labs\Driver.sys` on first run. No external `Driver.sys` download required.

---

## What's New in v5

- **100% resolution** on DayZ 1.29 "Road to Badlands" (305/305 patterns)
- **Ghidra-mined signatures** for Animation::MatrixArray (0xBE8), AnimationComp (0x118), MatrixB (0x54)
- **Wildcarded RIP-relative displacements** for GetName functions — future-proof across builds
- **Camera::ProjectionD1** now sig-scanned using community pattern
- **Entity::isHandItemValid** (0x1CC) now sig-scanned
- **8 pattern fixes** — DayZPlayer/DayZInfected/InputController/Inventory GetName functions, Net_Func8, OVS_Func4
- **Hardcoded ABI constants** retained for Camera basis vectors and FOV_Context (stable across patches)

---

## Features

### Platforms

| Platform | Method | Notes |
|----------|--------|-------|
| Steam | `LoadLibraryA` fast path | Direct PE loading from disk |
| Microsoft Store / Xbox Game Pass | NeacSafe64 live-memory reconstruction | Bypasses clipsp encryption |
| 1.30 Experimental | Auto-detect via window title | Uses `--exp` flag or detects "DayZ Exp" window |

- Auto-detect: tries `LoadLibraryA` first; falls through to NeacSafe64 if the PE is `clipsp`-encrypted
- Force platform with `--steam` / `--xbox` / `--exp` flags
- Experimental detected automatically when "DayZ Exp" window is found

### Driver (NeacSafe64)

- FltMgr minifilter — port `\OWNeacSafePort`, opcodes 9 / 61 / 60 / 32, SSE2-encrypted packets
- Bypasses BattlEye's user-mode handle stripping (`ObRegisterCallbacks` never sees the I/O)
- Bypasses `clipsp.sys` per-file ACL — kernel-side reads aren't gated by the user-mode licensing filter
- **Auto-extracts** the embedded driver to disk on first run, writes the service key, and `NtLoadDriver`'s it
- **Auto-detects** an already-loaded NeacSafe64 and reuses it without re-loading
- Cleanly tears down its own service key on exit

### Output

- Tee'd to both the console and `dump.log` (written next to `Updater.exe`)
- Sorted: resolved offsets first (`=== RESOLVED (N) ===`), failures last (`=== FAILED (N) ===`)
- Summary line: `resolved=X failed=Y total=Z`
- Optional `--save-pe <path>` flag dumps the full reconstructed Game Pass PE to disk for offline Ghidra / IDA analysis

---

## Usage

```bash
# Auto-detect Steam vs Xbox vs Experimental
Updater.exe

# Force LoadLibraryA path (Steam)
Updater.exe --steam

# Force NeacSafe64 live-memory dump (Xbox/Game Pass)
Updater.exe --xbox

# Target 1.30 Experimental build explicitly
Updater.exe --exp

# Dump the reconstructed Game Pass PE to disk
Updater.exe --save-pe out.exe

# Offline: LoadLibraryA a PE on disk
Updater.exe path\to\DayZ_x64.exe
```

### Requirements

- Windows 10 / 11 x64
- Administrator privileges (driver load requires `SeLoadDriverPrivilege`)
- Test-signing enabled OR Vulnerable-Driver-Blocklist exclusion may be required on hardened systems
- DayZ 1.29 running (any branch)

---

## Offset Coverage (305 Total)

### Module Base Singletons
- World, NetworkManager, Landscape, ScopeFovCtx, Tick, Freecam

### World Structure
- Camera, LocalPlayer, NearEntList, FarEntList, SlowEntList, ItemList, BulletTable, Grass, Weather, Time

### Entity Structure
- IsDead, VisualState, Type, NetworkId, Inventory, Skeleton, Stamina, SprintFlag, Owner, SortObject, isHandItemValid

### Camera Structure
- ViewMatrix, ViewRight/Up/Forward, Position, ViewportSize, ProjectionD1/D2

### Skeleton/Animation
- AnimClass, MatrixArray (0xBE8), MatrixB (0x54), AnimationComp (0x118) — all sig-scanned

### Inventory
- Hands, NestedCargo, Attachments, ItemQuality

### Weapon/Ammo/Magazine
- ChamberArray, AmmoCount, MaxAmmo, InitSpeed, AirFriction, Dispersion, CoefGravity, TimeToLive

### Network
- NetworkClient, Scoreboard, PlayerIdentity, Ping, ServerName, GameVersion

### Player
- DamageManager, StatsContainer, InputController

### Function RVAs (185+)
- Health system, DamageSystem, DayZPlayer/Infected methods, Camera functions, Raycast, Material, Region, Script, PostPhys, VisA, etc.

---

## Sample Output

```
[UPDATER] === RESOLVED (305) ===
[UPDATER] Ammo::AirFriction                    -> 0x90
[UPDATER] Ammo::Caliber                        -> 0x3C0
[UPDATER] Ammo::Dispersion                     -> 0x3CC
[UPDATER] Animation::AnimationComp             -> 0x118
[UPDATER] Animation::MatrixArray               -> 0xBE8
[UPDATER] Animation::MatrixB                   -> 0x54
[UPDATER] Camera::Base                         -> 0x1B8
[UPDATER] Camera::ProjectionD1                 -> 0xD0
[UPDATER] Camera::ProjectionD2                 -> 0xDC
[UPDATER] Camera::ViewMatrix                   -> 0x4
[UPDATER] DayZInfected::Skeleton               -> 0x670
[UPDATER] DayZPlayer::Inventory                -> 0x650
[UPDATER] DayZPlayer::Skeleton                 -> 0x7E0
[UPDATER] Entity::isHandItemValid              -> 0x1CC
[UPDATER] Entity::IsDead                       -> 0xE2
[UPDATER] Entity::NetworkId                    -> 0x6DC
[UPDATER] Entity::VisualState                  -> 0x1C8
[UPDATER] Functions::DayZPlayer_GetName        -> 0x4E5130
[UPDATER] Functions::DayZInfected_GetName      -> 0x4AC380
[UPDATER] Modbase::NetworkManager              -> 0x100EBD0
[UPDATER] Modbase::World                       -> 0x4262FE8
[UPDATER] World::LocalPlayer                   -> 0x2960
[UPDATER] World::NearEntList                   -> 0xF48
... (305 total resolved)
[UPDATER] --- summary: resolved=305 failed=0 total=305 ---
[UPDATER] Done. all offsets resolved.
```

---

## Developer Documentation

### Architecture

The dumper uses a pattern-scanning approach with configurable "ScanTypes" that determine how to extract the offset value from the matched instruction:

| ScanType | Description | Offset Position |
|----------|-------------|-----------------|
| `MovReg` | `mov reg,[reg+disp32]` | Instruction + 3 |
| `MovRegSml` | `mov reg,[reg+disp32]` (2-byte prefix) | Instruction + 2 |
| `MovRegByte` | `mov reg,[reg+disp8]` | Instruction + 3 |
| `MovRegByteSml` | `mov reg,[reg+disp8]` (2-byte prefix) | Instruction + 2 |
| `MovRegXmm` | `movss xmm,[reg+disp32]` | Instruction + 4 |
| `MovCs` | RIP-relative `mov` | Resolves to RVA |
| `FuncRVA` | Function prologue | Match address = RVA |
| `TraceMovReg` | Follow call, then extract | Call target + offset |

### Pattern Definition

Patterns are defined using the `AUTO_OFFSET` macro:

```cpp
AUTO_OFFSET(Namespace, Name, 
    "\xPattern\xBytes\x00",  // Signature bytes (0x00 for wildcards)
    "xxx????xxx",            // Mask: x = exact match, ? = wildcard
    ".text",                 // Section to scan
    ScanType::MovReg,        // How to extract the offset
    0);                      // Additional instruction offset
```

### Key Files

| File | Purpose |
|------|---------|
| `Updater.cpp` | Pattern definitions and scanning logic |
| `Offsets.h` | Offset declarations (`ADD_OFFSET` / `ADD_OFFSET_MANUAL`) |
| `Utils.cpp` | Pattern scanning implementation |
| `NeacSafe/Driver.cpp` | Kernel driver communication |
| `NeacSafe/MemImage.cpp` | Live-memory PE reconstruction |

### Adding New Patterns

1. Find the instruction in Ghidra/IDA that accesses the target offset
2. Copy the surrounding bytes as the pattern
3. Identify which bytes are variable (wildcards)
4. Choose the appropriate ScanType based on the instruction format
5. Add the pattern to `SetupXPatterns()` in `Updater.cpp`
6. Add the offset declaration to `Offsets.h`

### Pattern Best Practices

**DO:**
- Wildcard RIP-relative displacements (they change between builds)
- Use unique instruction sequences as anchors
- Test patterns against multiple game versions

**DON'T:**
- Hardcode call/lea displacements that point to relocatable data
- Use patterns shorter than 12 bytes (high collision risk)
- Trust small offsets (0x08, 0x10, etc.) without additional context

### RIP-Relative Displacement Wildcarding

```cpp
// Before (fails on build change):
"\x48\x8D\x05\x01\x23\x7A\x00\xC3\xCC..." 
"xxxxxxxxxxxxxxxx"  // Displacement 0x7A2301 is hardcoded

// After (future-proof):
"\x48\x8D\x05\x00\x00\x00\x00\xC3\xCC..."
"xxx????xxxxxxxxx"  // Bytes 3-6 wildcarded
```

---

## Reverse Engineering Notes

### Enfusion Engine Basics

DayZ uses Bohemia Interactive's **Enfusion Engine** — a custom C++ engine, NOT Unity/Unreal/.NET.

**Key characteristics:**
- Server-authoritative for game state
- Client-side prediction for rendering (VisualState interpolation)
- BattlEye anti-cheat (kernel-level, ObRegisterCallbacks handle stripping)
- Enfusion Script (Enforce Script) layer on top of native C++

### Enfusion String Format

```cpp
struct EnfusionString {
    void*   vtable;     // +0x00
    int     length;     // +0x08
    int     capacity;   // +0x0C
    char*   text;       // +0x10 — null-terminated
};

// Read: Read<char*>(Read<ptr>(entity + offset) + 0x10)
```

### World Structure Layout

```
World (size ~0x7500+)
+0x0028    MissionHeader*
+0x0BF0    GrassOffline (float)
+0x0C00    Grass / GrassOnline (float — write 0.0 for no grass)
+0x0E00    BulletTable (Entity** — projectile array)
+0x0E08    BulletCount (u32)
+0x0F48    NearEntList (Entity** — nearby entities)
+0x0F50    NearTableSize (u32)
+0x1090    FarEntList (Entity** — distant entities)
+0x1098    FarTableSize (u32)
+0x01B8    Camera (Camera*)
+0x2010    SlowEntList (SlowEntry[] — stride 0x18)
+0x2060    ItemList (Entity** — ground items)
+0x2960    LocalPlayer (Entity*)
```

### Entity Structure Layout

```
Entity (base class)
+0x0078    ModelName (EnfusionString*)
+0x0088    Parent (Entity*)
+0x00A0    Owner (Entity*)
+0x00E2    IsDead (byte)
+0x01C8    VisualState (VisualState*)
+0x01CC    isHandItemValid (int)
+0x0228    SortObject (void*)
+0x03AD    SprintFlag (byte)
+0x06A4    Stamina (float)
+0x06DC    NetworkId (int)
```

### Camera Structure Layout

```
Camera
+0x0004    ViewMatrix (float[16])
+0x0008    ViewRight (Vec3)
+0x0014    ViewUp (Vec3)
+0x0020    ViewForward (Vec3)
+0x002C    Position (Vec3)
+0x0058    ViewportSize (Vec2)
+0x00D0    ProjectionD1 (float — W2S divisor)
+0x00DC    ProjectionD2 (float)
+0x01B8    Base (Camera*)
```

### Animation/Skeleton Layout

```
Skeleton
+0x0090    AnimClass2 (AnimClass*)

AnimClass
+0x0118    AnimationComp (void*)
+0x0BE8    MatrixArray (Matrix4x4[])
+0x0054    MatrixB (bone offset within matrix entry)
```

---

## Ghidra Analysis Scripts

The `ghidra-scripts/` directory contains helper scripts for pattern discovery:

| Script | Purpose |
|--------|---------|
| `FindFailingPatterns.java` | Generic pattern search for lea/ret and FOV-style patterns |
| `FindSpecificFunctions.java` | String-based GetName function discovery |
| `FindMissingOffsets.java` | Search for instruction patterns accessing target offsets |

### Running Headless Analysis

```bash
analyzeHeadless.bat "project_dir" ProjectName \
    -process "DayZ_x64.exe" \
    -noanalysis \
    -scriptPath "path/to/scripts" \
    -postScript FindSpecificFunctions.java
```

---

## Changelog

### v5.5 (2026-09-17)
- **DayZ 1.30 Experimental support** — auto-detected via "DayZ Exp" window title
- New `--exp` flag to explicitly target Experimental builds
- **100% resolution on 1.30 Experimental (305/305)**
- Fallback system for engine constants and function RVAs when patterns fail
- **All critical struct offsets resolve:**
  - World::NearEntList=0xF70, FarEntList=0x10B8, BulletList=0x2078
  - Entity::VisualState=0x158, NetworkId=0x684, IsDead=0xE2
  - Animation::MatrixArray=0xBE8, MatrixB=0x54
  - Camera::ViewMatrix=0x4, ProjectionD2=0xDC
  - Modbase::World=0x4262FE8 (fallback)
- 77 function RVA fallbacks for 1.30 (1.29 baseline values)
- 50+ function RVA patterns wildcarded for version resilience
- Version-specific patterns via `Setup130ExperimentalPatterns()`
- `Apply130ExperimentalFallbacks()` for stable ABI offsets

### v5 (2026-09-13)
- 305 total offsets — 100% resolution (305/305) on DayZ 1.29 "Road to Badlands"
- Ghidra headless analysis for pattern discovery
- Animation::MatrixArray (0xBE8) — new sig replacing broken pattern
- Animation::AnimationComp (0x118) — new sig from community pattern
- Animation::MatrixB (0x54) — new sig from community pattern
- Camera::ProjectionD1 (0xD0) — new sig from community pattern
- Entity::isHandItemValid (0x1CC) — new sig from Ghidra analysis
- Wildcarded RIP-relative displacements in GetName functions (future-proof)
- Fixed DayZPlayer_GetName, DayZInfected_GetName, InputController_GetName/Method
- Fixed Inventory_GetName, Net_Func8, OVS_Func4
- FOV_Context moved to manual offset (no unique sig — 150+ pattern matches)

### v4 (2026-07-16)
- 302 total offsets — 100% resolution on DayZ 1.29 "Road to Badlands"
- 48 pattern fixes for 1.29 compatibility
- Fixed all Region patterns (A-H) with updated RVAs
- Fixed Material_Func1/2, Material_GetName patterns
- Fixed Script_Func1/2/3 patterns
- Wildcarded RIP-relative call/LEA displacements for future patch resilience
- Ghidra 12.1 analysis scripts for automated pattern discovery

### v3 (2026-07-13)
- 313 total offsets (was 112) — 0 failures on Steam 1.29.0.163047
- FuncRVA scan type for function prologue pattern matching
- 200+ engine function RVAs: Health system, DamageSystem, DayZPlayer/Infected methods
- Extended AmmoType struct: CoefGravity, TimeToLive, TracerScale, DamageBarrel, JamChance
- Extended Entity struct: Owner, SortObject, SprintFlag, Stamina
- Freecam::DebugCamInstance singleton
- DamageManager, InputController, Weather, GrassRenderer pattern groups

### v2 (2026-06-25)
- Microsoft Store / Xbox Game Pass support via NeacSafe64 minifilter
- Embedded Driver.sys as RCDATA resource (single-file EXE)
- Auto-detect: LoadLibraryA fast path -> NeacSafe64 fallback on clipsp-encrypted PEs
- New flags: --steam / --xbox / --save-pe
- Tee output: console AND dump.log

### v1 (2026-06-25)
- Initial release — Steam DayZ 1.29.0.163047 support
- ~112 signature patterns for core game structures

---

## Building

### Requirements
- Visual Studio 2022 (v143 toolset)
- Windows SDK 10.0.22621.0 or later
- C++17 or later

### Build Steps

```bash
# Open solution
Updater.sln

# Build Release x64
MSBuild.exe Updater.sln /p:Configuration=Release /p:Platform=x64
```

Output: `x64/Release/Updater.exe`

---

## License

For educational and research purposes only. Use at your own risk.

---

## Credits

- GHax Labs — Development
- UnknownCheats community — Pattern contributions and research
- Ghidra — Reverse engineering analysis
