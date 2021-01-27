#pragma once

#include <stdint.h>

#include "types.h"

void create_dir(const char* dir_name);
void hammer_session(SessionConfig * cfg, MemoryBuffer * memory);
void fuzzing_session(SessionConfig * cfg, MemoryBuffer * memory);
void benchmark_best_pattern(SessionConfig * cfg, MemoryBuffer * mem, int d, int v);
