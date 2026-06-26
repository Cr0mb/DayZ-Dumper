#include "Framework.h"

Updater* g_Updater = new Updater;

static void PrintUsage() {
	printf(
		"Usage: Updater.exe [--steam | --xbox] [--save-pe <path>] [<pe_path>]\n"
		"  (no args)         auto-detect: LoadLibraryA the running DayZ_x64.exe;\n"
		"                    if that fails (Game Pass build), reconstruct the\n"
		"                    image via NeacSafe64 minifilter.\n"
		"  --steam           force LoadLibraryA path; abort on failure.\n"
		"  --xbox            force NeacSafe64 live-memory dump (Game Pass binaries).\n"
		"  --save-pe <path>  after a NeacSafe64 reconstruction, also write the\n"
		"                    reconstructed image to <path> for static analysis.\n"
		"  <pe_path>         LoadLibraryA the given .exe directly (no live game).\n"
	);
}

int main(int argc, char** argv) {

	// Parse flags. The first non-flag positional is treated as a path override.
	for (int i = 1; i < argc; ++i) {
		const char* a = argv[i];
		if (!a || !a[0]) continue;
		if (!_stricmp(a, "--steam"))      { g_Updater->m_Platform = Updater::Platform::Steam; continue; }
		if (!_stricmp(a, "--xbox") ||
			!_stricmp(a, "--gamepass"))   { g_Updater->m_Platform = Updater::Platform::Xbox;  continue; }
		if (!_stricmp(a, "--save-pe")) {
			if (i + 1 >= argc) { printf("[UPDATER] --save-pe requires a path argument\n"); return 0; }
			const char* p = argv[++i];
			size_t n = strlen(p);
			if (n >= MAX_PATH) n = MAX_PATH - 1;
			memcpy(g_Updater->m_SavePeTo, p, n);
			g_Updater->m_SavePeTo[n] = '\0';
			continue;
		}
		if (!_stricmp(a, "--help") ||
			!_stricmp(a, "-h"))           { PrintUsage(); return 0; }
		if (a[0] == '-')                  { printf("[UPDATER] unknown flag: %s\n", a); PrintUsage(); return 0; }
		// Positional path override
		size_t n = strlen(a);
		if (n >= MAX_PATH) n = MAX_PATH - 1;
		memcpy(g_Updater->m_PathOverride, a, n);
		g_Updater->m_PathOverride[n] = '\0';
		printf("[UPDATER] Path override: %s\n", g_Updater->m_PathOverride);
	}

	switch (g_Updater->m_Platform) {
		case Updater::Platform::Steam: printf("[UPDATER] platform = STEAM (forced)\n"); break;
		case Updater::Platform::Xbox:  printf("[UPDATER] platform = XBOX / Game Pass (forced)\n"); break;
		default:                        printf("[UPDATER] platform = AUTO (LoadLibraryA -> ASTRA64 fallback)\n"); break;
	}

	// Open the tee log file (next to Updater.exe) BEFORE any work so every
	// line — init, sig setup, scan, resolved offsets — lands in both the
	// console and dump.log. Replaces the prior freopen trick that silenced
	// the console output entirely.
	teelog::Open();

	if (!g_Updater->Init()) {
		TLOG("[UPDATER] Init failed!\n");
		teelog::Close();
		return 1;
	}

	if (!g_Updater->Scan()) {
		TLOG("[UPDATER] Scanning Failed!\n");
		teelog::Close();
		return 1;
	}

	bool allHit = g_Updater->Release();
	TLOG("[UPDATER] Done. %s\n", allHit ? "all offsets resolved." : "some offsets failed (see above).");
	teelog::Close();
	return 0;
}
