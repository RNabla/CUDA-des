#pragma once

#include <cstdint>

#pragma region headers

__host__ __device__ uint64_t create_pattern(uint64_t combination_number, const char* alphabet, int32_t alphabet_length,
                                            int32_t segment_length);

__host__ __device__ uint64_t number_of_combinations(const int alphabet_length, int segment_length);


#pragma endregion

#pragma region implementation

__host__ __device__ uint64_t create_pattern(uint64_t combination_number, const char* alphabet, int32_t alphabet_length,
                                            int32_t segment_length)
{
	int limit = 8 - segment_length;
	uint64_t acc = 0;
	for (int i = 8; --i >= limit;)
	{
		uint64_t y = combination_number / alphabet_length;
		acc *= (1ULL << 8);
		acc += alphabet[combination_number - y * alphabet_length];
		combination_number = y;
	}
	acc *= (1ULL << (8 * limit));
	return acc;
}

__host__ __device__ uint64_t number_of_combinations(const int alphabet_length, int segment_length)
{
	uint64_t result = 1;
	while (segment_length--)
		result *= alphabet_length;
	return result;
}


#pragma endregion
