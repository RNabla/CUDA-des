#pragma once

#include "cuda_runtime.h"
#include <cstdint>

#pragma region headers

template<class T>
__host__ __device__ uint64_t create_pattern(uint64_t combination_number, const T* alphabet,
                                            const int32_t alphabet_length,
                                            const int32_t segment_length);

__host__ uint64_t number_of_combinations(const int alphabet_length, const int segment_length);

__host__ void hex_dump(const uint64_t value, const bool flush = false, const int length = 16,
                       const int group = 2);

__host__ void show_results(const uint64_t* const keys, const uint64_t* const plaintexts, const int count,
                           const int output_limit);

#pragma endregion

#pragma region implementation

template<class T>
__host__ __device__ uint64_t create_pattern(uint64_t combination_number, const T* alphabet,
                                            const int32_t alphabet_length,
                                            const int32_t segment_length)
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

__host__ uint64_t number_of_combinations(const int alphabet_length, int segment_length)
{
	uint64_t result = 1;
	while (segment_length--)
		result *= alphabet_length;
	return result;
}

__host__ void hex_dump(const uint64_t value, const bool flush, const int length, const int group)
{
	const char* hex = "0123456789abcdef";
	int counter = 0;
	for (int i = length; --i >= 0;)
	{
		int c = (value & (0xfULL << i * 4)) >> i * 4;
		printf("%c", hex[c]);
		if (++counter % group == 0)
			printf(" ");
	}
	printf(" | ");
	for (int i = length / 2; --i >= 0;)
	{
		int c = (value & (0xffULL << i * 8)) >> i * 8;
		if (32 <= c && c <= 126)
			printf("%c", (char)c);
		else
			printf(".");
	}
	if (flush)
		printf("\n");
}


__host__ void show_results(const uint64_t* const keys, const uint64_t* const plaintexts, const int count,
                           const int output_limit)
{
	if (count <= 0)
	{
		printf("No results found\n");
		return;
	}
	printf("Results: \n");
	int limit = count;
	if (limit > output_limit)
		limit = output_limit;
	for (int i = 0; i < limit; i++)
	{
		printf("%d # Key: ", i);
		hex_dump(keys[i]);
		printf("\tPlaintext: ");
		hex_dump(plaintexts[i]);
		printf("\n");
	}
	if (output_limit < count)
	{
		printf("\tAnd %d more matches...", count - output_limit);
	}
	printf("\n");
}


#pragma endregion
