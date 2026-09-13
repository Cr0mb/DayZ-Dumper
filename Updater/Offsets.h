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
	ADD_OFFSET_MANUAL(PlayerIdentity, SteamID, 0xA0);	// 0xA0 — SteamID Enfusion string in identity record
	ADD_OFFSET_MANUAL(PlayerIdentity, NetworkID, 0x30);	// 0x30 — NetworkID in ScoreboardIdentity

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

/* AmmoType Extended — NEW v16 */
	ADD_OFFSET(AmmoType, TimeToLive);					// 0x3D8 — float, bullet lifetime
	ADD_OFFSET(AmmoType, CoefGravity);					// 0x3BC — float, gravity coefficient
	ADD_OFFSET(AmmoType, TracerScale);					// 0x408 — float
	ADD_OFFSET(AmmoType, TracerStartTime);				// 0x40C — float
	ADD_OFFSET(AmmoType, TracerEndTime);				// 0x410 — float
	ADD_OFFSET(AmmoType, DamageBarrel);					// 0x418 — float
	ADD_OFFSET(AmmoType, JamChance);					// 0x420 — float
	ADD_OFFSET(AmmoType, ProjectileCount);				// 0x3D0 — int (shotgun pellets)
	ADD_OFFSET(AmmoType, SimulationStep);				// 0x3B8 — float
	ADD_OFFSET(AmmoType, TypicalSpeed);					// 0x398 — float
	ADD_OFFSET(AmmoType, MaxLeadSpeed);					// 0x394 — float

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
	ADD_OFFSET(VisualState, Transform);					// DONE (sig-scanned)
	ADD_OFFSET(VisualState, InverseTransform);			// DONE (sig-scanned)
	ADD_OFFSET_MANUAL(VisualState, Velocity, 0x54);		// NEW v16 — 0x54
	ADD_OFFSET_MANUAL(VisualState, Direction, 0x20);	// NEW v16 — 0x20
	ADD_OFFSET_MANUAL(VisualState, Position, 0x2C);		// 0x2C — world position (same as Transform[9..11])
	ADD_OFFSET_MANUAL(VisualState, DirX, 0x20);			// 0x20 — direction X component
	ADD_OFFSET_MANUAL(VisualState, DirY, 0x28);			// 0x28 — direction Y component
	ADD_OFFSET_MANUAL(Modbase, FOV_Context, 0x1008CE0);	// MANUAL — no unique sig (150+ matches)
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

/* Network Extended — NEW v16 */
	ADD_OFFSET_MANUAL(Network, ScoreboardTable, 0x18);	// 0x18 — IdentityRecord*[] from NetworkClient
	ADD_OFFSET(Network, ScoreboardSize);				// 0x24 — player count from NetworkClient (sig-scanned)
	ADD_OFFSET_MANUAL(Network, MissionHeaderPtr, 0x28);	// 0x28 — MissionHeader* from NetworkClient
	ADD_OFFSET_MANUAL(Network, IdentitySize, 0x170);	// 0x170 — sizeof(IdentityRecord)
	ADD_OFFSET_MANUAL(Network, SteamID, 0xA0);			// 0xA0 — Enfusion string in identity record
	ADD_OFFSET(Network, ThirdPersonFlag);				// 0x9C — inverted bool at NetworkClient (sig-scanned)
	ADD_OFFSET_MANUAL(Network, CrosshairFlag, 0xA0);	// 0xA0 — inverted bool at NetworkClient
	ADD_OFFSET_MANUAL(Network, PlayerCount, 0x20);		// 0x20 — player count (adjacent to scoreboard table)

/* Weapon Auto-Extracted */
	ADD_OFFSET(Weapon, ChamberArray);
	ADD_OFFSET(Weapon, AttachmentsSize);
	ADD_OFFSET(Weapon, AttachmentsArray);
	ADD_OFFSET(Weapon, ChamberEntrySize);

/* Weapon Extended — NEW v16 */
	ADD_OFFSET(Weapon, MuzzleCount);					// 0x6BC — number of muzzle entries
	ADD_OFFSET(Weapon, InitSpeedMultiplier);			// 0x960 — float, default 1.0
	ADD_OFFSET(Weapon, MuzzleArray);					// 0x6B0 — muzzle entry array (stride 0x100)

/* Camera Auto-Extracted */
	ADD_OFFSET(Camera, ProjectionD2);
	ADD_OFFSET(Camera, Base);
	ADD_OFFSET_MANUAL(Camera, ViewportSize, 0x58);		// 0x58 — viewport size (x=width, y=height)

/* Camera Extended — NEW v16 */
	ADD_OFFSET_MANUAL(Camera, Position, 0x2C);			// 0x2C — camera world position (Vec3)
	ADD_OFFSET_MANUAL(Camera, ViewRight, 0x08);			// 0x08 — right basis vector (Vec3)
	ADD_OFFSET_MANUAL(Camera, ViewUp, 0x14);			// 0x14 — up basis vector (Vec3)
	ADD_OFFSET_MANUAL(Camera, ViewForward, 0x20);		// 0x20 — forward basis vector (Vec3)
	ADD_OFFSET(Camera, ProjectionD1);					// 0xD0 — projection divisor 1 (sig-scanned)
	ADD_OFFSET_MANUAL(Camera, StateFlags, 0x1A8);		// 0x1A8 — freecam state flags
	ADD_OFFSET_MANUAL(Camera, UpdateInterval, 0x1C0);	// 0x1C0 — camera update interval
	ADD_OFFSET_MANUAL(Camera, AspectRatio, 0x6C);		// 0x6C — viewport aspect ratio
	ADD_OFFSET_MANUAL(Camera, FOV_TermA, 0x4C);			// 0x4C — FOV calculation term A
	ADD_OFFSET_MANUAL(Camera, FOV_TermB, 0x50);			// 0x50 — FOV calculation term B
	ADD_OFFSET_MANUAL(Camera, InvertedViewRight, 0x8);	// 0x8 — inverted view right (same as transform)
	ADD_OFFSET_MANUAL(Camera, InvertedViewUp, 0x14);	// 0x14 — inverted view up
	ADD_OFFSET_MANUAL(Camera, InvertedViewForward, 0x20);	// 0x20 — inverted view forward
	ADD_OFFSET_MANUAL(Camera, InvertedViewTranslation, 0x2C);	// 0x2C — inverted view translation

/* Animation Auto-Extracted — Updated 2026-09-13 with Ghidra-mined patterns */
	ADD_OFFSET(Animation, MatrixArray);					// 0xBE8 — bone matrix array (sig-scanned)
	ADD_OFFSET(Animation, MatrixB);						// 0x54 — bone offset within matrix entry (sig-scanned)
	ADD_OFFSET(Animation, AnimationComp);				// 0x118 — AnimClass (skeleton -> anim, sig-scanned)

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
	ADD_OFFSET_MANUAL(Inventory, NestedCargoCount, 0x44);	// 0x44 — nested cargo item count

/* Entity Auto-Extracted */
	ADD_OFFSET(Entity, IsDead);
	ADD_OFFSET(Entity, EntityDead);
	ADD_OFFSET(Entity, NetworkId);
	ADD_OFFSET(Entity, FutureVisualState);
	ADD_OFFSET(Entity, Type);
	ADD_OFFSET(Entity, VisualState);

/* Entity Extended — NEW v16 */
	ADD_OFFSET_MANUAL(Entity, Parent, 0x88);			// 0x88 — parent entity ptr
	ADD_OFFSET(Entity, Owner);							// 0xA0 — owning entity ptr (sig-scanned)
	ADD_OFFSET_MANUAL(Entity, ModelName, 0x78);			// 0x78 — Enfusion string (model path / validity)
	ADD_OFFSET(Entity, Stamina);						// 0x6A4 — stamina float (sig-scanned)
	ADD_OFFSET(Entity, SprintFlag);						// 0x3AD — byte, sprinting state (sig-scanned)
	ADD_OFFSET(Entity, SortObject);						// 0x228 — spatial cell pointer (sig-scanned)
	ADD_OFFSET(Entity, isHandItemValid);				// 0x1CC — hand item validity flag (sig-scanned)

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

/* World Extended — NEW v16 */
	ADD_OFFSET(World, SlowEntCount);					// 0x2020 — live slow entity count
	ADD_OFFSET(World, ItemList2);						// 0x2080 — second item hash (drops/inventoryItem)
	ADD_OFFSET(World, ItemList2Size);					// 0x2088 — second item hash size
	ADD_OFFSET(World, TimeMultiplier);					// 0x29A0 — time speed multiplier
	ADD_OFFSET(World, MissionHeader);					// 0x28 — MissionHeader* ptr

/* Infected Auto-Extracted */
	ADD_OFFSET(Infected, Skeleton);

/* Player Auto-Extracted */
	ADD_OFFSET(Player, InputController);
	ADD_OFFSET(Player, Skeleton);

/* DamageManager Internals — NEW v16 */
	ADD_OFFSET(DamageManager, GlobalHealth);			// 0x08 — float, max 100.0
	ADD_OFFSET(DamageManager, Blood);					// hash key "Blood", value ~5000
	ADD_OFFSET(DamageManager, Shock);					// hash key "Shock", value ~100
	ADD_OFFSET(DamageManager, InitFlags);				// 0x00 — byte, 0x0101 when valid
	ADD_OFFSET(DamageManager, HashCapacity);			// 0x20 — hash table capacity
	ADD_OFFSET(DamageManager, HashEntries);				// 0x28 — hash data array (16-byte stride)

/* InputController Extended — NEW v16 */
	ADD_OFFSET(InputController, AimChangeX);			// 0x14 — float, yaw delta
	ADD_OFFSET(InputController, AimChangeXFlags);		// 0x18 — DWORD, bottom 2 bits
	ADD_OFFSET(InputController, AimChangeY);			// 0x1C — float, pitch delta
	ADD_OFFSET(InputController, AimChangeYFlags);		// 0x20 — DWORD
	ADD_OFFSET(InputController, MoveSpeed);				// 0x24 — float, override
	ADD_OFFSET(InputController, MoveSpeedFlags);		// 0x28 — DWORD
	ADD_OFFSET(InputController, MoveEnabled);			// 0x30 — byte
	ADD_OFFSET(InputController, MeleeEvade);			// 0x34 — byte
	ADD_OFFSET(InputController, RaiseFlag);				// 0x3C — byte, weapon raised
	ADD_OFFSET(InputController, FreelookFlag);			// 0x4C — byte

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

/* === v16 Extended: Weather System === */
	ADD_OFFSET(Weather, Overcast);						// 0x10 — float (via WeatherController ptr chain)
	ADD_OFFSET(Weather, Fog);							// 0x18 — float
	ADD_OFFSET(Weather, Rain);							// 0x20 — float
	ADD_OFFSET(Weather, Snowfall);						// 0x28 — float
	ADD_OFFSET(Weather, StormDensity);					// 0x94 — float 0-1
	ADD_OFFSET(Weather, StormThreshold);				// 0x98 — float 0-1
	ADD_OFFSET(Weather, FogHeightDensity);				// 0x40 — float
	ADD_OFFSET(Weather, FogDistDensity);				// 0x48 — float

/* === v16 Extended: Grass Renderer === */
	ADD_OFFSET(GrassRenderer, ATOC);					// 0x80 — byte, alpha-to-coverage
	ADD_OFFSET(GrassRenderer, LOD);						// 0x100 — DWORD 0-3
	ADD_OFFSET(GrassRenderer, Quality);					// 0x104 — DWORD 0 or 1
	ADD_OFFSET(GrassRenderer, DistMax);					// 0x108 — float 32-199
	ADD_OFFSET(GrassRenderer, DistMin);					// 0x10C — float
	ADD_OFFSET(GrassRenderer, DistRatio);				// 0x110 — float
	ADD_OFFSET(GrassRenderer, Falloff);					// 0x114 — float
	ADD_OFFSET(GrassRenderer, FalloffBias);				// 0x118 — float

/* === v16 Extended: Function RVAs (sig-scanned) === */
	ADD_OFFSET(Functions, SetObjectMaterial);			// engine material setter
	ADD_OFFSET(Functions, GetObjectMaterial);			// engine material getter
	ADD_OFFSET(Functions, SetMaterialSlot);				// low-level material slot setter
	ADD_OFFSET(Functions, PhysicsRaycast);				// Landscape::ObjectCollisionLine
	ADD_OFFSET(Functions, FindClassByName);				// Enfusion script class lookup
	ADD_OFFSET(Functions, GetBonePositionWS);			// native bone world-pos calculator
	ADD_OFFSET(Functions, SpeedhackTick);				// tick speed global pattern

/* === 2026-07-12: Ghidra ChamsBypass function RVAs === */
	ADD_OFFSET(Functions, LoadMaterial);				// 0x969A90 — material loading with refcount
	ADD_OFFSET(Functions, VisualStateAccessor);			// 0x703E40 — returns ptr to global VisualState
	ADD_OFFSET(Functions, DirtyInvalidate);				// 0x716AA0 — marks visual state dirty
	ADD_OFFSET(Functions, RefcountRelease);				// 0x33AEF0 — generic refcount release / destructor
	ADD_OFFSET(Functions, MaterialTableAlloc);			// 0x473360 — hash table insert for material map
	ADD_OFFSET(Functions, MaterialTableFind2);			// 0x4752F0 — alternate hash table lookup
	ADD_OFFSET(Functions, StringAllocator);				// 0x2B5B10 — Enfusion string construction

/* === 2026-07-13: Ghidra/Scanner4 function RVAs === */
	ADD_OFFSET(Functions, LoadOrCreateMaterial);		// 0x96BD30 — material create-or-get
	ADD_OFFSET(Functions, NetworkStateDispatcher);		// 0x0C3A80 — network state machine
	ADD_OFFSET(Functions, SendWrapper1);				// 0x0AB9180 — network send helper 1
	ADD_OFFSET(Functions, SendWrapper2);				// 0x0AB9D00 — network send helper 2
	ADD_OFFSET(Functions, MaterialReloadHelper);		// 0x46CDB0 — material reload logic
	ADD_OFFSET(Functions, DirtyInvalidateHelper1);		// 0x465D70 — dirty/invalidate sub 1
	ADD_OFFSET(Functions, DirtyInvalidateHelper2);		// 0x45B0F0 — dirty/invalidate sub 2
	ADD_OFFSET(Functions, DirtyInvalidateHelper3);		// 0x45BDC0 — dirty/invalidate sub 3
	ADD_OFFSET(Functions, DirtyInvalidateHelper4);		// 0x46B280 — dirty/invalidate sub 4
	ADD_OFFSET(Functions, RefcountDecHelper);			// 0x08B0C0 — refcount decrement helper
	ADD_OFFSET(Functions, InnerDestructor);				// 0x9F0210 — inner dtor / virtual cleanup
	ADD_OFFSET(Functions, MaterialArenaAlloc);			// 0xBE7200 — arena allocator for materials
	ADD_OFFSET(Functions, MaterialResolve);				// 0x968480 — material name resolver
	ADD_OFFSET(Functions, BufferGrow);					// 0x0E26A0 — dynamic buffer grow

/* === 2026-07-13: ObjectVisualState VTable function RVAs (Ghidra) === */
	// VTable 1 — primary ObjectVisualState vtable
	ADD_OFFSET(Functions, OVS_VT1_Construct);			// 0x7B7440 — VT1[0]
	ADD_OFFSET(Functions, OVS_VT1_CopyFields);			// 0x9309F0 — VT1[1]
	ADD_OFFSET(Functions, OVS_VT1_InitCopy);			// 0x930D20 — VT1[4]
	ADD_OFFSET(Functions, OVS_VT1_InitZero);			// 0x930870 — VT1[5]
	ADD_OFFSET(Functions, OVS_VT1_TransformCopy);		// 0x9308A0 — VT1[8]
	ADD_OFFSET(Functions, OVS_VT1_Compare);				// 0x923C20 — VT1[9]
	ADD_OFFSET(Functions, OVS_VT1_FullInit);			// 0x926630 — VT1[10]
	ADD_OFFSET(Functions, OVS_VT1_Subtract);			// 0x7B7790 — VT1[11]
	ADD_OFFSET(Functions, OVS_VT1_SmallSub);			// 0x7B7224 — VT1[12]
	ADD_OFFSET(Functions, OVS_VT1_NullCheck);			// 0x053B80 — VT1[13]
	ADD_OFFSET(Functions, OVS_VT1_Noop);				// 0x058C20 — VT1[14]
	// VTable 2 — secondary ObjectVisualState vtable
	ADD_OFFSET(Functions, OVS_VT2_Delegator);			// 0x7B7380 — VT2[3]
	ADD_OFFSET(Functions, OVS_VT2_Wrapper1);			// 0x7BA4D0 — VT2[4]
	ADD_OFFSET(Functions, OVS_VT2_Wrapper2);			// 0x7BA4F0 — VT2[5]
	ADD_OFFSET(Functions, OVS_VT2_Wrapper3);			// 0x7BA510 — VT2[6]
	ADD_OFFSET(Functions, OVS_VT2_Wrapper4);			// 0x7BA450 — VT2[7]
	ADD_OFFSET(Functions, OVS_VT2_Wrapper5);			// 0x7BA430 — VT2[8]
	ADD_OFFSET(Functions, OVS_VT2_Wrapper6);			// 0x7BA470 — VT2[9]
	ADD_OFFSET(Functions, OVS_VT2_FlagSet);				// 0x7B8860 — VT2[10]
	ADD_OFFSET(Functions, OVS_VT2_ComplexInit);			// 0x7B9610 — VT2[11]
	ADD_OFFSET(Functions, OVS_VT2_LargeFrame);			// 0x7B7740 — VT2[12]
	// Additional Ghidra functions
	ADD_OFFSET(Functions, InterlockedDecHelper);		// 0x0896B0 — interlocked dec helper

/* === 2026-07-13: String xref / collision research function RVAs === */
	// DamageSystem
	ADD_OFFSET(Functions, DamageSystem_GetHealth);		// 0x429C10 — health reader
	ADD_OFFSET(Functions, DamageSystem_Apply);			// 0x4829DA — damage application
	ADD_OFFSET(Functions, DamageSystem_VTEntry);		// 0x7B89E0 — vtable entry point
	// Health subsystem
	ADD_OFFSET(Functions, Health_GetMax);				// 0x4217B0 — max health getter
	ADD_OFFSET(Functions, Health_SetValue);				// 0x422550 — health value setter
	ADD_OFFSET(Functions, Health_Clamp);				// 0x4227D0 — health clamping
	ADD_OFFSET(Functions, Health_GetPercent);			// 0x422CE0 — percentage calc
	ADD_OFFSET(Functions, Health_Regen);				// 0x4263B0 — regeneration logic
	ADD_OFFSET(Functions, Health_Damage);				// 0x427DD0 — damage handler
	ADD_OFFSET(Functions, Health_Heal);					// 0x428B80 — heal handler
	ADD_OFFSET(Functions, Health_Update);				// 0x429844 — health update
	ADD_OFFSET(Functions, Health_Tick);					// 0x429E10 — per-tick update
	ADD_OFFSET(Functions, Health_Calc);					// 0x42B670 — calculation
	ADD_OFFSET(Functions, Health_Internal);				// 0x817870 — internal helper
	// DayZPlayer methods
	ADD_OFFSET(Functions, DayZPlayer_GetName);			// 0x4E4FA0 — player name accessor
	ADD_OFFSET(Functions, DayZPlayer_Update1);			// 0x4E5670 — player update 1
	ADD_OFFSET(Functions, DayZPlayer_Update2);			// 0x4F22B0 — player update 2
	ADD_OFFSET(Functions, DayZPlayer_Method);			// 0x500F80 — player method
	// DayZInfected methods
	ADD_OFFSET(Functions, DayZInfected_GetName);		// 0x4AC1F0 — infected name accessor
	ADD_OFFSET(Functions, DayZInfected_Update);			// 0x4AC300 — infected update
	ADD_OFFSET(Functions, DayZInfected_Method);			// 0x4ACD80 — infected method
	// InputController
	ADD_OFFSET(Functions, InputController_GetName);		// 0x518C70 — HumanInputController name
	ADD_OFFSET(Functions, InputController_Method);		// 0x518C80 — HumanInputController method
	// Camera
	ADD_OFFSET(Functions, Camera_Func);					// 0x4B6970 — camera function
	// Inventory
	ADD_OFFSET(Functions, Inventory_GetName);			// 0x542170 — inventory name accessor
	// Material
	ADD_OFFSET(Functions, Material_Func1);				// 0x2804BB — material function 1
	ADD_OFFSET(Functions, Material_GetName);			// 0x298E30 — material name accessor
	ADD_OFFSET(Functions, Material_Func2);				// 0x2AC3C0 — material function 2
	// Blood
	ADD_OFFSET(Functions, Blood_Func);					// 0x4A9000 — blood function
	// Physics / Collision
	ADD_OFFSET(Functions, AllocateCollisionBuffer);		// 0x98450  — collision buffer alloc
	ADD_OFFSET(Functions, FreeCollisionBuffer);			// 0x987E0  — collision buffer free
	ADD_OFFSET(Functions, FilterIgnoreTwo_Init);		// 0x4B76E0 — physics filter init
	// Texture
	ADD_OFFSET(Functions, GetObjectTexture);			// 0x473850 — object texture getter
	ADD_OFFSET(Functions, SetObjectTexture);			// 0x478F30 — object texture setter

/* === 2026-07-13: Scanner7 function RVAs === */
	// Float-constant / health-calc functions
	ADD_OFFSET(Functions, HealthCalc_1);				// 0x962C0  — 100.0 float const func
	ADD_OFFSET(Functions, HealthCalc_2);				// 0x1B9A10 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_3);				// 0x338690 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_4);				// 0x3898D0 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_5);				// 0x407160 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_6);				// 0x419680 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_7);				// 0x421610 — health-related
	ADD_OFFSET(Functions, HealthCalc_8);				// 0x780440 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_9);				// 0x79C120 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_10);				// 0x7A05C0 — 100.0 float func
	ADD_OFFSET(Functions, HealthCalc_11);				// 0xAFC590 — 100.0 float func
	// Blood max
	ADD_OFFSET(Functions, BloodMax_Func);				// 0x10EC80 — 5000.0 float = max blood
	// Network functions
	ADD_OFFSET(Functions, Net_Func1);					// 0xAB040
	ADD_OFFSET(Functions, Net_Func2);					// 0xABEC0
	ADD_OFFSET(Functions, Net_Func3);					// 0xABF70
	ADD_OFFSET(Functions, Net_Func4);					// 0xABFC0
	ADD_OFFSET(Functions, Net_Func5);					// 0xAC200
	ADD_OFFSET(Functions, Net_Func6);					// 0xAC2B0
	ADD_OFFSET(Functions, Net_Func7);					// 0xAC340
	ADD_OFFSET(Functions, Net_Func8);					// 0xAC540
	ADD_OFFSET(Functions, Net_Func9);					// 0xAC5F0
	ADD_OFFSET(Functions, Net_Func10);					// 0xACAE0
	ADD_OFFSET(Functions, Net_Func11);					// 0xACB20
	ADD_OFFSET(Functions, Net_Func12);					// 0xACBA0
	ADD_OFFSET(Functions, Net_Func13);					// 0xACBF0
	ADD_OFFSET(Functions, Net_Func14);					// 0xACC50
	ADD_OFFSET(Functions, Net_Func15);					// 0xACCD0
	// Script functions
	ADD_OFFSET(Functions, Script_Func1);				// 0x31C280
	ADD_OFFSET(Functions, Script_Func2);				// 0x31C400
	ADD_OFFSET(Functions, Script_Func3);				// 0x33AD40
	// DayZInfected helpers
	ADD_OFFSET(Functions, InfectedHelper1);				// 0x4AC120
	ADD_OFFSET(Functions, InfectedHelper2);				// 0x4AC150
	// DirtyInvalidate area
	ADD_OFFSET(Functions, DirtyInvalidateArea1);		// 0x7BD090
	// Physics-adjacent
	ADD_OFFSET(Functions, PhysicsAdj_Func1);			// 0x912460
	// Unknown
	ADD_OFFSET(Functions, Unknown_Func1);				// 0x73F090

/* === 2026-07-13: Scanner Temp Batch (24 functions from 8 regions) === */
	// RegionA (0x0D0000-0x100000)
	ADD_OFFSET(Functions, RegionA_Func1);				// 0x0D0000
	ADD_OFFSET(Functions, RegionA_Func2);				// 0x0D0FD0
	ADD_OFFSET(Functions, RegionA_Func3);				// 0x0D2420
	// RegionB (0x140000-0x200000)
	ADD_OFFSET(Functions, RegionB_Func1);				// 0x1401B0
	ADD_OFFSET(Functions, RegionB_Func2);				// 0x141A10
	ADD_OFFSET(Functions, RegionB_Func3);				// 0x143060
	// RegionC (0x200000-0x300000)
	ADD_OFFSET(Functions, RegionC_Func1);				// 0x2000B0
	ADD_OFFSET(Functions, RegionC_Func2);				// 0x2001C0
	ADD_OFFSET(Functions, RegionC_Func3);				// 0x200220
	// RegionD (0x500000-0x600000)
	ADD_OFFSET(Functions, RegionD_Func1);				// 0x500BC0
	ADD_OFFSET(Functions, RegionD_Func2);				// 0x500BE0
	ADD_OFFSET(Functions, RegionD_Func3);				// 0x500C30
	// RegionE (0x600000-0x700000)
	ADD_OFFSET(Functions, RegionE_Func1);				// 0x600E20
	ADD_OFFSET(Functions, RegionE_Func2);				// 0x600FD0
	ADD_OFFSET(Functions, RegionE_Func3);				// 0x601020
	// RegionF (0x800000-0x900000)
	ADD_OFFSET(Functions, RegionF_Func1);				// 0x8003B0
	ADD_OFFSET(Functions, RegionF_Func2);				// 0x800660
	ADD_OFFSET(Functions, RegionF_Func3);				// 0x800700
	// RegionG (0xA00000-0xAB0000)
	ADD_OFFSET(Functions, RegionG_Func1);				// 0xA000B0
	ADD_OFFSET(Functions, RegionG_Func2);				// 0xA00100
	ADD_OFFSET(Functions, RegionG_Func3);				// 0xA00140
	// RegionH (0xAD0000-0xB00000)
	ADD_OFFSET(Functions, RegionH_Func1);				// 0xAD0490
	ADD_OFFSET(Functions, RegionH_Func2);				// 0xAD38E0
	ADD_OFFSET(Functions, RegionH_Func3);				// 0xAD7D70

/* === 2026-07-13: Scanner Temp Batch 2 (45 functions from 9 regions) === */
	// Early region (0x030000-0x0AB000)
	ADD_OFFSET(Functions, Early_Func1);					// 0x042CF0
	ADD_OFFSET(Functions, Early_Func2);					// 0x06B870
	ADD_OFFSET(Functions, Early_Func3);					// 0x06DB90
	ADD_OFFSET(Functions, Early_Func4);					// 0x077920
	ADD_OFFSET(Functions, Early_Func5);					// 0x0AADB0
	// MidA region (0x340000-0x380000)
	ADD_OFFSET(Functions, MidA_Func1);					// 0x354B50
	ADD_OFFSET(Functions, MidA_Func2);					// 0x356470
	ADD_OFFSET(Functions, MidA_Func3);					// 0x36E1D0
	ADD_OFFSET(Functions, MidA_Func4);					// 0x375470
	ADD_OFFSET(Functions, MidA_Func5);					// 0x37B3C0
	// MidB region (0x420000-0x460000)
	ADD_OFFSET(Functions, MidB_Func1);					// 0x441980
	ADD_OFFSET(Functions, MidB_Func2);					// 0x444C20
	ADD_OFFSET(Functions, MidB_Func3);					// 0x450000
	ADD_OFFSET(Functions, MidB_Func4);					// 0x450010
	ADD_OFFSET(Functions, MidB_Func5);					// 0x45FF60
	// VisA region (0x700000-0x730000)
	ADD_OFFSET(Functions, VisA_Func1);					// 0x70B480
	ADD_OFFSET(Functions, VisA_Func2);					// 0x7113D0
	ADD_OFFSET(Functions, VisA_Func3);					// 0x71DB00
	ADD_OFFSET(Functions, VisA_Func4);					// 0x7226B0
	ADD_OFFSET(Functions, VisA_Func5);					// 0x72C290
	// VisB region (0x730000-0x780000)
	ADD_OFFSET(Functions, VisB_Func1);					// 0x735CE0
	ADD_OFFSET(Functions, VisB_Func2);					// 0x73AB20
	ADD_OFFSET(Functions, VisB_Func3);					// 0x7725C0
	ADD_OFFSET(Functions, VisB_Func4);					// 0x77ACD0
	ADD_OFFSET(Functions, VisB_Func5);					// 0x77FE90
	// OVS region (0x7B0000-0x800000)
	ADD_OFFSET(Functions, OVS_Func1);					// 0x7B3E20
	ADD_OFFSET(Functions, OVS_Func2);					// 0x7BE020
	ADD_OFFSET(Functions, OVS_Func3);					// 0x7BE030
	ADD_OFFSET(Functions, OVS_Func4);					// 0x7F2DE0
	ADD_OFFSET(Functions, OVS_Func5);					// 0x7FF9F0
	// PostPhys region (0x920000-0x960000)
	ADD_OFFSET(Functions, PostPhys_Func1);				// 0x941C10
	ADD_OFFSET(Functions, PostPhys_Func2);				// 0x949560
	ADD_OFFSET(Functions, PostPhys_Func3);				// 0x94D310
	ADD_OFFSET(Functions, PostPhys_Func4);				// 0x953680
	ADD_OFFSET(Functions, PostPhys_Func5);				// 0x95FD90
	// Mat region (0x960000-0x9B0000)
	ADD_OFFSET(Functions, Mat_Func1);					// 0x979E30
	ADD_OFFSET(Functions, Mat_Func2);					// 0x983FA0
	ADD_OFFSET(Functions, Mat_Func3);					// 0x986E60
	ADD_OFFSET(Functions, Mat_Func4);					// 0x99A260
	ADD_OFFSET(Functions, Mat_Func5);					// 0x9A7EC0
	// Late region (0xB00000-0xC00000)
	ADD_OFFSET(Functions, Late_Func1);					// 0xB430C0
	ADD_OFFSET(Functions, Late_Func2);					// 0xB5F460
	ADD_OFFSET(Functions, Late_Func3);					// 0xB962D0
	ADD_OFFSET(Functions, Late_Func4);					// 0xBB4790
	ADD_OFFSET(Functions, Late_Func5);					// 0xBE7F06

/* === 2026-07-13: Speedhack === */
	ADD_OFFSET(Modbase, Speedhack);						// 0x348684 — speedhack tick global cmp

/* === v16 Extended: Modbase Additions === */
	ADD_OFFSET(Modbase, DLC_MapManager);				// 0x1008028 — DLC map manager singleton
	ADD_OFFSET(Modbase, FOV_Base);						// 0x100A7D8 — FOV base singleton

/* === v16 Extended: Freecam === */
	ADD_OFFSET(Freecam, CameraMode);					// global — set to 3 for debug cam
	ADD_OFFSET(Freecam, DebugCamInstance);				// global — FreeDebugCamera instance ptr

/* === v16 Extended: HumanCommand === */
	ADD_OFFSET(HumanCommand, Additives);				// player + 0x2FB0

/* === v16 Extended: Physics Body === */
	ADD_OFFSET(PhysicsBody, BodyFlags);					// 0x1AC — uint32, bit 0 = sleeping/dead
}
