#pragma once

#include <rosetta_config/Config.h>

// Populated by runtime_loader before init_library is called.
// Stored in __DATA,config so the loader can write to it directly.
extern RosettaConfig kConfig;
