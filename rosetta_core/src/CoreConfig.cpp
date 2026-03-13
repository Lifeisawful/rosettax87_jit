#include "rosetta_core/CoreConfig.h"

const RosettaConfig* g_rosetta_config = nullptr;

void rosetta_set_config(const RosettaConfig* config) {
    g_rosetta_config = config;
}
