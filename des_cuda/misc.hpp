#pragma once

#include <cstdint>

void hex_dump(const uint64_t value, const bool flush = false, const int length = 16,
	const int group = 2);

void show_results(const uint64_t* const keys, const uint64_t* const plaintexts, const int count,
	const int output_limit);
