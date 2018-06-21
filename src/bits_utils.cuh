#pragma once

#include <cstdint>

#pragma region headers

__device__ __host__ uint64_t rotate_left(const uint64_t val, const int rotations);

__device__ __host__ uint64_t setbit(const uint64_t from, uint64_t to, const int position_from,
                                    const int position_to);

__device__ __host__ uint64_t permutate(const uint64_t value, const int* permutation_matrix,
                                       const int matrix_length);

#pragma endregion

#pragma region implementation

__device__ __host__ uint64_t rotate_left(const uint64_t val, const int rotations)
{
	uint64_t result = val;
	result |= val >> 28;
	result <<= rotations;
	result &= 0xfffffffULL << 36;
	return result;
}

__device__ __host__ uint64_t setbit(const uint64_t from, uint64_t to, const int position_from,
                                    const int position_to)
{
	if ((from & (1ULL << (63 - position_from))) > 0)
		to |= (1ULL << (63 - position_to));
	return to;
}

__device__ __host__ uint64_t permutate(const uint64_t value, const int* permutation_matrix,
                                       const int matrix_length)
{
	uint64_t result = 0;
	for (auto i = 0; i < matrix_length; i++)
		result = setbit(value, result, permutation_matrix[i] - 1, i);
	return result;
}

#pragma endregion
