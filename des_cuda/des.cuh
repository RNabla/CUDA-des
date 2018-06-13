#pragma once

#include "bits_utils.cuh"
#include "des_utils.cuh"

#pragma region headers

__host__ __device__ void generate_round_keys(const uint64_t master_key, uint64_t* const round_keys);

__host__ __device__ uint64_t des_encrypt(const uint64_t plaintext, const uint64_t* round_keys);
#pragma endregion

#pragma region implementation

__host__ __device__ void generate_round_keys(const uint64_t master_key, uint64_t* const round_keys)
{
	const int* rot;

#if __CUDA_ARCH__
	rot = d_rot;
#else
	rot = h_rot;
#endif

	uint64_t pc1 = permutated_choice_1(master_key);

	uint64_t c0 = pc1 & (0xfffffffULL << 36);
	uint64_t d0 = (pc1 & (0xfffffffULL << 8)) << 28;

	for (auto i = 0; i < 16; i++)
	{
		uint64_t cn = rotate_left(c0, rot[i]);
		uint64_t dn = rotate_left(d0, rot[i]);

		c0 = cn;
		d0 = dn;
		round_keys[i] = permutated_choice_2(cn, dn);
	}
}

__host__ __device__ uint64_t des_encrypt(const uint64_t plaintext, const uint64_t* round_keys)
{
	uint64_t result = initial_permutation(plaintext);

	uint64_t left = result >> 32 << 32;
	uint64_t right = result << 32;

	for (auto i = 0; i < 16; i++)
	{
		uint64_t prev_right = right;
		uint64_t prev_left = left;
		left = prev_right;
		right = prev_left ^ f(prev_right, round_keys[i]);
	}

	uint64_t preoutput = right | left >> 32;
	result = initial_permutation_reverse(preoutput);
	return result;
}


#pragma endregion
