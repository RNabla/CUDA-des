#pragma once

#include "bits_utils.cuh"
#include "des_constants.cuh"

#pragma region headers

__host__ __device__ uint64_t initial_permutation(const uint64_t plaintext, const int* ip);

__host__ __device__ uint64_t initial_permutation_reverse(const uint64_t preoutput, const int* ip_rev);

__host__ __device__ uint64_t permutated_choice_1(const uint64_t master_key, const int* pc1);

__host__ __device__ uint64_t permutated_choice_2(const uint64_t c, const uint64_t d, const int* pc2);

__host__ __device__ uint64_t f(uint64_t r, const uint64_t key, const int *e, const int *p, const int *s);

#pragma endregion


#pragma region implementation

__host__ __device__ uint64_t initial_permutation(const uint64_t plaintext, const int* ip)
{
	return permutate(plaintext, ip, 64);
}

__host__ __device__ uint64_t initial_permutation_reverse(const uint64_t preoutput, const int* ip_rev)
{
	return permutate(preoutput, ip_rev, 64);
}


__host__ __device__ uint64_t permutated_choice_1(const uint64_t master_key, const int* pc1)
{
	return permutate(master_key, pc1, 56);
}


__host__ __device__ uint64_t permutated_choice_2(const uint64_t c, const uint64_t d, const int* pc2)
{
	return permutate(c | d >> 28, pc2, 48);
}


__host__ __device__ uint64_t f(uint64_t r, const uint64_t key, const int *e, const int *p, const int *s)
{
	r = permutate(r, e, 48);
	r ^= key;

	uint64_t result = 0;
	for (int i = 0; i < 8; i++)
	{
		int left = (r & (1ULL << (63 - 6 * i))) >> (63 - 6 * i);
		int right = (r & (1ULL << (58 - 6 * i))) >> (58 - 6 * i);

		int outer = left << 1 | right;
		int inner = (r & (0xFULL << (59 - 6 * i))) >> (59 - 6 * i);


		uint64_t piece = s[i * 64 + (outer << 4 | inner)];

		result ^= piece << (60 - 4 * i);
	}
	return permutate(result, p, 32);
}

#pragma endregion
