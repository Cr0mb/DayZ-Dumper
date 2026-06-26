# DayZ-Dumper

> Live-memory PE signature scanner for DayZ 1.29 — Steam + Microsoft Store / Game Pass

**DayZ-Dumper** is a one-shot offset extractor.

Run `Updater.exe` and it pattern-scans the running `DayZ_x64.exe` for approximately **112 known signatures**, prints the resolved RVAs and structure offsets, and writes a `dump.log` next to the executable.

Supports both:

- Steam
- Microsoft Store / Xbox Game Pass

The Game Pass version cannot normally be opened from user mode because `clipsp.sys` blocks access to the encrypted executable. DayZ-Dumper works around this by communicating with the **NeacSafe64** minifilter driver, allowing reconstruction of the decrypted PE directly from memory before performing the signature scan.

---

## Single-file Design

The driver is embedded as an **RCDATA** resource inside `Updater.exe`.

On first launch it automatically extracts to:

```text
%LOCALAPPDATA%\GHax Labs\Driver.sys
```

No external driver download is required.

---

# Features

## Platforms

- Steam (DayZ 1.29.0.163047)
  - Uses `LoadLibraryA` on the on-disk executable

- Microsoft Store / Xbox Game Pass (DayZ 1.29.6.0)
  - Uses NeacSafe64 live-memory reconstruction

- Automatic platform detection
- Falls back to NeacSafe64 when `clipsp` encryption is detected
- Manual selection via:

```text
--steam
--xbox
```

---

## Driver

- NeacSafe64 FltMgr minifilter
- Uses `\OWNeacSafePort`
- Supports opcodes:
  - 9
  - 32
  - 60
  - 61
- SSE2 encrypted packets
- Bypasses BattlEye handle stripping
- Bypasses `clipsp.sys`
- Automatically extracts and loads the embedded driver
- Reuses an already-loaded NeacSafe64 instance when available
- Removes its temporary service key on exit

---

## Output

- Console output
- `dump.log`
- Alphabetically sorted resolved offsets
- Failed signatures listed separately
- Summary:

```text
resolved=X
failed=Y
total=Z
```

Optional:

```text
--save-pe <path>
```

Saves the reconstructed Game Pass executable for Ghidra or IDA.

---

## Coverage

- Approximately 112 signatures
- Modbase
- World
- Network
- Player
- Entity
- Inventory
- Weapon
- Ammo
- Magazine
- Camera
- Skeleton
- VisualState

Additional features:

- Reads all eight PE sections
- Resolves Xbox-shifted RVAs automatically
- Shared ABI between Steam and Game Pass

---

# Usage

1. Launch DayZ.
2. Run `Updater.exe` as Administrator.
3. Watch the console or open `dump.log`.

```bash
Updater.exe

Updater.exe --steam

Updater.exe --xbox

Updater.exe --save-pe out.exe

Updater.exe path\to\DayZ_x64.exe
```

---

# Requirements

- Windows 10 / 11 x64
- Administrator privileges
- Test Signing enabled or Vulnerable Driver Blocklist exclusion
- DayZ 1.29 running

---

### Xbox Notes

The 68 missing signatures are typically caused by **cold-page artifacts**, not engine changes.

The sample above was collected from the main menu. Signatures tied to gameplay (combat, inventory, networking, etc.) resolve after spending several minutes in-game.

When scanned during gameplay, the resolved count generally exceeds **80**.

Where signatures resolve on both platforms, structure offsets are byte-identical between Steam 1.29.0 and Game Pass 1.29.6.

---

# Changelog

## 2026-06-25 (v2)

```text
Added Xbox/Microsoft Store support

Added NeacSafe64 live-memory reconstruction

Embedded Driver.sys

Automatic Steam/Game Pass detection

New flags:
    --steam
    --xbox
    --save-pe

Added dump.log output

Sorted output

Fixed numerous Xbox signatures
```
