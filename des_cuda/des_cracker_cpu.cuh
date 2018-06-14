#pragma once

#include <cstdint>
#include <cstring>
#include "misc.cuh"
#include "des.cuh"

#pragma region headers

__host__ int cpu_brute_force(const char* alphabet, const int key_length, const int plaintext_length, const uint64_t ciphertext,
                    uint64_t* const plaintexts, uint64_t* const keys, const int output_size);

__host__ void run_cpu_version(const char* alphabet, const int key_length, const int plaintext_length, const uint64_t ciphertext,
	const int output_limit);

#pragma endregion

#pragma region implementation


__host__  int cpu_brute_force(const char* alphabet, const int key_length, const int plaintext_length, const uint64_t ciphertext,
                    uint64_t* const plaintexts, uint64_t* const keys, const int output_size)
{
	size_t alphabet_length = strlen(alphabet);
	uint64_t key_combinations = number_of_combinations(alphabet_length, key_length);
	uint64_t plaintext_combinations = number_of_combinations(alphabet_length, plaintext_length);
	uint64_t round_keys[16];

	int count = 0;
	for (uint64_t i = 0; i < key_combinations; i++)
	{
		uint64_t key = create_pattern(i, alphabet, alphabet_length, key_length);
		generate_round_keys(key, round_keys);
		
		for (uint64_t j = 0; j < plaintext_combinations; j++)
		{
			uint64_t plaintext = create_pattern(j, alphabet, alphabet_length, plaintext_length);
			if (ciphertext == des_encrypt(plaintext, round_keys))
			{
				if (count < output_size)
				{
					keys[count] = key;
					plaintexts[count] = plaintext;
				}
				count++;
			}
		}
		key = next_combination(key, alphabet, alphabet_length, 1);
	}
	return count;
}

__host__ void run_cpu_version(const char* alphabet, const int key_length, const int plaintext_length, const uint64_t ciphertext,
	const int output_limit)
{
	uint64_t* plaintexts = new uint64_t[output_limit];
	uint64_t* keys = new uint64_t[output_limit];

	int count = cpu_brute_force(alphabet, key_length, plaintext_length, ciphertext, plaintexts, keys, output_limit);

	show_results(keys, plaintexts, count, output_limit);

	delete[] plaintexts;
	delete[] keys;
}

#pragma endregion
