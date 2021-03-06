#pragma once

#include <stdint.h>

#include "types.h"

void create_dir(const char* dir_name);
void hammer_session(SessionConfig * cfg, MemoryBuffer * memory);
void fuzzing_session(SessionConfig * cfg, MemoryBuffer * memory, bool random_fuzzing, int hammer_count, bool random_pattern);
void benchmark_best_pattern(SessionConfig *cfg, MemoryBuffer *mem, int d, int v, int bank_no, long special_rows[]);
