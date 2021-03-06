#pragma once

#include <cstdint>
#include <cstring>
#include <chrono>
#include "misc.cuh"
#include "des.cuh"

#pragma region headers

__host__ int cpu_brute_force(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                             const int plaintext_length, const uint64_t ciphertext,
                             uint64_t* const plaintexts, uint64_t* const keys);

__host__ void run_cpu_version(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                              const int plaintext_length, const uint64_t ciphertext);

#pragma endregion

#pragma region implementation

__host__ int cpu_brute_force(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                             const int plaintext_length, const uint64_t ciphertext,
                             uint64_t* const plaintexts, uint64_t* const keys)
{
	int32_t key_alphabet_length = (int32_t)strlen(key_alphabet);
	int32_t plaintext_alphabet_length = (int32_t)strlen(plaintext_alphabet);
	uint64_t key_combinations = number_of_combinations(key_alphabet_length, key_length);
	uint64_t plaintext_combinations = number_of_combinations(plaintext_alphabet_length, plaintext_length);
	uint64_t round_keys[16];
	int count = 0;
	for (uint64_t i = 0; i < key_combinations; i++)
	{
		//printf("\r%d / %d", i, key_combinations);
		uint64_t key = create_pattern(i, key_alphabet, key_alphabet_length, key_length);
		generate_round_keys(key, round_keys, h_rot, h_pc1, h_pc2);

		for (uint64_t j = 0; j < plaintext_combinations; j++)
		{
			uint64_t plaintext = create_pattern(j, plaintext_alphabet, plaintext_alphabet_length, plaintext_length);
			if (ciphertext == des_encrypt(plaintext, round_keys, h_ip, h_ip_rev, h_e, h_p, h_s))
			{
				*keys = key;
				*plaintexts = plaintext;
				count = 1;
			}
		}
	}
	return count;
}

__host__ void run_cpu_version(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                              const int plaintext_length, const uint64_t ciphertext)
{
	printf("=== CPU ===\n");
	std::chrono::steady_clock::time_point cpu_start, cpu_end;

	uint64_t plaintext,
	         key;

	cpu_start = std::chrono::high_resolution_clock::now();
	int count = cpu_brute_force(key_alphabet, key_length, plaintext_alphabet, plaintext_length, ciphertext, &plaintext,
	                            &key);
	cpu_end = std::chrono::high_resolution_clock::now();
	show_results(&key, &plaintext, count);
	printf("CPU time (all)             [ms]: %llu\n",
	       std::chrono::duration_cast<std::chrono::milliseconds>(cpu_end - cpu_start).count());
}

#pragma endregion
