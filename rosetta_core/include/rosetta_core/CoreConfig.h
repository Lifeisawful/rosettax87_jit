#pragma once

struct RosettaConfig;

extern const RosettaConfig* g_rosetta_config;

void rosetta_set_config(const RosettaConfig* config);
