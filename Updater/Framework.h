#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#if _DEBUG
#include <iostream>
#include <unordered_map>
#else 
#include <vector>
#endif

#include "Offsets.h"

#include "Utils.h"
#include "Updater.h"
