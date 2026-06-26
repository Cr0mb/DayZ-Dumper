#pragma once

typedef __int64 INT64;

#define ADD_OFFSET_MANUAL(Klass, Name, Value)	namespace Klass { inline INT64 Name = Value; }
#define ADD_OFFSET(Klass, Name)					ADD_OFFSET_MANUAL(Klass, Name, 0x0)

// ─── Gap inventory ────────────────────────────────────────────────────────
// Offsets actively used by the DayZInternalBase overlay and/or DayZ-External
// that the dumper does NOT currently produce. The cheats hardcode each of
// these from manual reversing; they will silently break on a binary update.
// Categorised by why they aren't sig-scanned:
//
//   [SUB-BYTE]   Universal small struct constants (0x8, 0xC, 0x10, 0x14, 0x20,
//                0x24, 0x2C, 0x38, 0x44, 0x54, 0x58, 0x88, 0xA0, 0xD0, 0xDC,
//                0xF8, 0x148, 0x150, 0x15C, 0x170, 0x1B0). These match too
//                many code sites to disambiguate via pattern alone — they're
//                better thought of as ABI/layout constants than mineable
//                signatures.
//
//   [MODBASE]    Module-base-relative singletons (Network::Manager 0x100FBD0,
//                FOV_Base 0x100A7D8, FOV_Context 0x1008CE0, DLC::MapManager
//                0x1008028, World::Instance 0x414A858, Tickness 0xF193C8).
//                These need a MovCs-method pattern at the *one* code site
//                that loads the global — same as Modbase::World already is.
//                Pattern revival attempted for Network::Manager 2026-05-19
//                and failed ( pattern too brittle for current
//                build); the others have no pattern published yet.
//
//   [LARGE]      Larger entity / world struct offsets that are realistic
//                sig-scan targets but don't yet have a working pattern:
//                Network::ServerName (0x308), Network::Ping (0x33C),
//                Network::GameVersion (0x350), Camera::FOV_VerticalTermA
//                (0x4C), Camera::FOV_VerticalTermB (0x50), World::CameraOn
//                (0x2968), World::ThirdPerson (0x74), World::MissionHeader
//                (0x28), Camera::Viewport (0x58), Camera::ProjectionD1
//                (0xD0), Camera::ProjectionD2 (0xDC), Magazine::AmmoTypePtr
//                (0x20), Weapon::ChamberedPtr (0x1B0), Weapon::AmmoCapacityA
//                (0x6B0), Weapon::AmmoCapacityB (0x6B4), Weapon::AmmoMagCount
//                (0x6AC), AmmoType::InitSpeed (0x38C), AmmoType::AirFriction
//                (0x3B4), AmmoType::Dispersion (0x3A4).
//
// To add a pattern: open DayZ_x64.exe in Ghidra, locate the disp32 / disp8
// load for the offset, copy the surrounding bytes + mask, append a new
// AUTO_OFFSET entry in the matching SetupXPatterns() function. The dumper
// will print "[UPDATER] X::Y -> 0xZ" on success or "Failed to get offset"
// on miss — log.txt for the canonical baseline.
// ──────────────────────────────────────────────────────────────────────────

namespace Offsets {

/* Module Base Offsets */
	ADD_OFFSET(Modbase, World);							// DONE
	ADD_OFFSET(Modbase, Network);						// OUTDATED ( revival attempted 2026-05-19, pattern failed to match — see Updater.cpp comment)
	ADD_OFFSET(Modbase, Tick);							// DONE
	// ADD_OFFSET(Modbase, ScriptContext);					// OUTDATED (no replacement in )

/* Network Offsets */
	// Network::Scoreboard / ScoreboardSize: no working sig yet — see
	// SetupNetworkPatterns. The cheat's expected values are NC+0x18 and
	// NC+0x24, which is what extract_all_offsets.py should rediscover
	// once a stable code-shape pattern is found.

/* PlayerIdentity Offsets */
	// Re-enabled 2026-06-04: NetworkManager is at ImageBase+0x100FC10. 
	// With the root pointer corrected the inner
	// identity layout (NetID/SteamID/PlayerName) is unchanged and can be
	// re-sig-scanned. The existing SetupPlayerIdentityPatterns + Network
	// patterns drive these via SIG.
	ADD_OFFSET(PlayerIdentity, Name);
	// ADD_OFFSET(PlayerIdentity, SteamID);   // no sig wired yet
	// ADD_OFFSET(PlayerIdentity, NetworkID); // no sig wired yet

/* World Offsets */
	ADD_OFFSET(World, BulletList);						// DONE
	ADD_OFFSET(World, BulletListSize);					// NEW 2026-06-03 (Ghidra-mined)
	ADD_OFFSET(World, ItemList);						// REVIVED 2026-06-03 (Ghidra-mined)
	ADD_OFFSET(World, ItemListSize);					// NEW 2026-06-03
	ADD_OFFSET(World, SlowEntList);						// NEW 2026-06-03
	ADD_OFFSET(World, NearEntList);						// DONE
	ADD_OFFSET(World, FarEntList);						// DONE
	ADD_OFFSET(World, Camera);							// DONE
	ADD_OFFSET(World, Grass);							// REVIVED 2026-06-03 (was GrassDensity)
	ADD_OFFSET(World, Hour);							// NEW 2026-06-03 (writes float const 0xBF32B8C3)
	ADD_OFFSET(World, Day);								// NEW 2026-06-03 (writes float const 0x3E860A92)
	ADD_OFFSET(World, EyeAccom);						// NEW 2026-06-03 (writes float 1.0f)
	ADD_OFFSET(World, LocalPlayer);						// SCAN-OK but returns 0x2958 — canonical per cheats is 0x2960 (TraceMovReg lands on adjacent field)
	ADD_OFFSET(World, LocalOffset);	// neg value		// DONE

/* Human Offsets */
	ADD_OFFSET(Human, HumanType);						// REVIVED 2026-06-03 (Ghidra-mined — load + null check pattern)
	ADD_OFFSET(Human, Quality);							// NEW 2026-06-03 (writes initial health = 30 / 0x1E)
	ADD_OFFSET(Human, IsDead);							// OUTDATED ( revival 2026-05-19 returned 0x430 — pattern too generic)
	ADD_OFFSET(Human, VisualState);						// DONE
	ADD_OFFSET(Human, LodShape);						// DONE

/* DayzInfected Offsets */
	ADD_OFFSET(DayZInfected, Skeleton);					// DONE

/* HumanType Offsets */
	ADD_OFFSET(HumanType, ObjectName);					// DONE
	ADD_OFFSET(HumanType, CategoryName);				// DONE
	ADD_OFFSET(HumanType, CleanName);					// NEW 2026-06-03 (0x518 — display name pointer)
	// ADD_OFFSET(HumanType, FullName); // NO PATTERN


/* DayZLocal Offsets */
	/* FIGURE OUT A WAY TO GET ENFUSION PTR - COULD BE FUCKING COOOOOOOL */

/* DayZPlayer Offsets */
	ADD_OFFSET(DayZPlayer, Skeleton);					// REVIVED 2026-06-03 (Ghidra-mined; 0x7E0)
	// ADD_OFFSET(DayZPlayer, NetworkID);					// OUTDATED
	ADD_OFFSET(DayZPlayer, Inventory);					// DONE

/* DayZPlayerInventory Offsets */
	ADD_OFFSET(DayZPlayerInventory, Hands);				// DONE

/* InventoryItem Offsets */
	ADD_OFFSET(InventoryItem, ItemInventory);			// DONE

/* Weapon Offsets */
	// ADD_OFFSET(Weapon, WeaponIndex);					// OUTDATED
	ADD_OFFSET(Weapon, WeaponInfoTable);				// DONE
	// ADD_OFFSET(Weapon, MuzzleCount);					// OUTDATED
	ADD_OFFSET(Weapon, WeaponInfoSize);					// DONE

/* WeaponInventory Offsets */
	// ADD_OFFSET(WeaponInventory, MagazineRef);			// OUTDATED

/* Magazine Offsets */
	// ADD_OFFSET(Magazine, MagazineType);					// OUTDATED
	ADD_OFFSET(Magazine, AmmoCount);					// REVIVED 2026-06-03 (0x3B0 — Ghidra-mined)
	ADD_OFFSET(Magazine, MaxAmmo);						// NEW 2026-06-03 (0x3A4)

/* AmmoType Offsets */
	ADD_OFFSET(AmmoType, InitSpeed);					// OUTDATED
	ADD_OFFSET(AmmoType, AirFriction);					// OUTDATED

/* Skeleton Offsets */
	// ADD_OFFSET(Skeleton, AnimClass1);					// OUTDATED
	ADD_OFFSET(Skeleton, AnimClass2);					// DONE

/* AnimClass Offsets */
	// ADD_OFFSET(AnimClass, MatrixArray);					// OUTDATED
	ADD_OFFSET_MANUAL(AnimClass, MatrixEntry, 0x54);	// HARDCODED

/* Camera Offsets */
	ADD_OFFSET(Camera, ViewMatrix);						// DONE
	// ADD_OFFSET(Camera, ViewPortMatrix);					// OUTDATED
	// ADD_OFFSET(Camera, ViewProjection);					// OUTDATED

/* VisualState Offsets */
	ADD_OFFSET(VisualState, Transform);					// DONE
	ADD_OFFSET(VisualState, InverseTransform);			// DONE
	// ADD_OFFSET(VisualState, Velocity);					// NO PATTERN
	ADD_OFFSET(Modbase, FOV_Context);
	ADD_OFFSET(Network, ServerName);
	ADD_OFFSET(Network, Ping);
	ADD_OFFSET(Network, GameVersion);
	ADD_OFFSET(Weapon, ChamberedPtr);
	ADD_OFFSET(Weapon, AmmoCapacityA);
	ADD_OFFSET(Weapon, AmmoCapacityB);
	ADD_OFFSET(Weapon, AmmoMagCount);
	ADD_OFFSET(AmmoType, Dispersion);
	ADD_OFFSET(HumanType, CleanNameInternal);

/* Ammo Auto-Extracted */
	ADD_OFFSET(Ammo, MagazineCapacityB);
	ADD_OFFSET(Ammo, FuseDistance);
	ADD_OFFSET(Ammo, MagazineCapacityA);
	ADD_OFFSET(Ammo, MagazineAmmoCount);
	ADD_OFFSET(Ammo, Dispersion);
	ADD_OFFSET(Ammo, AirFriction);
	ADD_OFFSET(Ammo, InitSpeed);
	ADD_OFFSET(Ammo, Caliber);
	ADD_OFFSET(Ammo, Hit);
	ADD_OFFSET(Ammo, IndirectHitRange);

/* Network Auto-Extracted */
	ADD_OFFSET_MANUAL(Network, ThirdPerson, 0x74);		// HARDCODED — MissionHeader::is_third_person_disabled. Engine-ABI fixed; the sig was resolving to 0x9C (adjacent DWORD field), silently breaking Force TP. See Updater.cpp comment.
	ADD_OFFSET(Network, ClientIdSize);
	ADD_OFFSET(Network, PlayerName);
	ADD_OFFSET(Network, ManagerNetworkClient);
	ADD_OFFSET(Network, Crosshair);

/* Weapon Auto-Extracted */
	ADD_OFFSET(Weapon, ChamberArray);
	ADD_OFFSET(Weapon, AttachmentsSize);
	ADD_OFFSET(Weapon, AttachmentsArray);
	ADD_OFFSET(Weapon, ChamberEntrySize);

/* Camera Auto-Extracted */
	ADD_OFFSET(Camera, ProjectionD2);
	ADD_OFFSET(Camera, Base);
	ADD_OFFSET(Camera, ViewportSize);

/* Animation Auto-Extracted */
	ADD_OFFSET(Animation, MatrixArray);
	ADD_OFFSET(Animation, MatrixB);
	ADD_OFFSET(Animation, AnimationComp);

/* Object_layout Auto-Extracted */
	ADD_OFFSET(Object_layout, MaterialArray);
	ADD_OFFSET(Object_layout, MaterialCount);
	ADD_OFFSET(Object_layout, HiddenSelectionState);

/* Modbase Auto-Extracted */
	ADD_OFFSET(Modbase, Landscape);
	ADD_OFFSET(Modbase, NetworkManager);

/* Inventory Auto-Extracted */
	ADD_OFFSET(Inventory, NestedInventory);
	ADD_OFFSET(Inventory, SlotCountAlt);
	ADD_OFFSET(Inventory, ItemQuality);
	ADD_OFFSET(Inventory, Hands);
	ADD_OFFSET(Inventory, NestedCargo);
	ADD_OFFSET(Inventory, NestedCargoCount);

/* Entity Auto-Extracted */
	ADD_OFFSET(Entity, IsDead);
	ADD_OFFSET(Entity, EntityDead);
	ADD_OFFSET(Entity, NetworkId);
	ADD_OFFSET(Entity, FutureVisualState);
	ADD_OFFSET(Entity, Type);
	ADD_OFFSET(Entity, VisualState);

/* HumanType Auto-Extracted */
	ADD_OFFSET(HumanType, Realclassname);

/* World Auto-Extracted */
	ADD_OFFSET(World, NearTableSize);
	ADD_OFFSET(World, SlowTableSize);
	ADD_OFFSET(World, BulletCount);
	ADD_OFFSET(World, TimeScale);
	ADD_OFFSET(World, PlayerOn);
	ADD_OFFSET(World, BulletTable);
	ADD_OFFSET(World, FarTableSize);
	ADD_OFFSET(World, GrassOffline);
	ADD_OFFSET(World, DayTime);
	ADD_OFFSET(World, WeatherController);
	ADD_OFFSET(World, GrassOnline);

/* Infected Auto-Extracted */
	ADD_OFFSET(Infected, Skeleton);

/* Player Auto-Extracted */
	ADD_OFFSET(Player, InputController);
	ADD_OFFSET(Player, Skeleton);

/* === 2026-06-10 batch: Ghidra-derived offsets (V16 cheat) === */

/* Player stats hash map */
	// Container ptr offset on the player entity (verified via Player::GetPlayerStats
	// at VA 0x7AD240 — `mov rcx,[rcx+0x6F0]`). Manual because it's a stable
	// struct-layout offset that's already known; the SIG path can verify it.
	ADD_OFFSET(Player, StatsContainer);
	// StatRecord float-value field at +0x2C (verified via PlayerStats::AddDelta
	// at VA 0x6ABA30 — `addss xmm1,[rcx+0x2C]; movss [rcx+0x2C],xmm1; ret`).
	ADD_OFFSET(PlayerStats, RecordValue);

/* Damage manager (Blood / Health 0..1 reads) */
	ADD_OFFSET(Player, DamageManager);

/* FOV singleton (modbase-relative). Float in degrees; the engine reads this
   each frame in the user-config FOV path. Confirmed via the CamResult thunk
   at 0x1405A3E60 — `cvttss2si edx, [rax+0x9C4]` after `mov rax,[rip+ctx]`. */
	ADD_OFFSET(Modbase, FovBase);

/* Scope FOV resolver context — different singleton than FovBase. The chain
   `ctx → flag/branch → [+0x4C]*[+0x50]` gives the live FOV multiplier. */
	ADD_OFFSET(Modbase, ScopeFovCtx);
}
