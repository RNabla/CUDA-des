#pragma once

#include "cuda_runtime.h"
#include <cstdint>
#include <algorithm>

#pragma region headers

__host__ void usage(char* name);

__host__ void check_cipher(char* cipher, char* prog_name);

__host__ void parse_runtime_parameters(int argc, char** argv, char** key_alphabet, int* key_length,
                                       char** plaintext_alphabet,
                                       int* plaintext_length, uint64_t* ciphertext, bool* run_cpu, bool* run_gpu);

__host__ char* transform_key_alphabet(char* key_alphabet, char* prog_name);

__host__ char* transform_plaintext_alphabet(char* plaintext_alphabet, char* prog_name);

__host__ void print_parameters(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                               const int plaintext_length, const uint64_t cipher, const bool run_cpu,
                               const bool run_gpu);


#pragma endregion

#pragma region implementation

__host__ void usage(char* name)
{
	printf("%s - CUDA DES Cracker - Andrzej Nowikowski - 2018\n\n", name);
	printf("Usage: \n");
	printf(
		"%s --cipher <hex> --key-alphabet <ASCII> [--key-length <length>] --text-alphabet <ASCII> [--text-length <length>] [--cpu] [--gpu]\n\n",
		name);
	printf("    --cipher <hex> \t\t Hexencoded cipher to match against\n");
	printf("    --key-alphabet <ASCII> \t Alphabet of the possible chars in key\n");
	printf("    --key-length <length=8> \t Length of the key to brute. Length should be between 1 and 8\n");
	printf("    --text-alphabet <ASCII> \t Alphabet of the possible chars in text\n");
	printf("    --text-length <length=8> \t Length of the plaintext to brute. Length should be between 1 and 8\n");
	printf("    --cpu \t\t\t Try run CPU version of cracker\n");
	printf("    --gpu \t\t\t Try run GPU version of cracker\n");
	exit(1);
}

__host__ void check_cipher(char* cipher, char* prog_name)
{
	if (cipher == nullptr)
	{
		printf("--cipher: Provided cipher is empty\n");
		usage(prog_name);
	}

	if (cipher[0] == '0' && cipher[1] == 'x')
		cipher += 2;

	int length = (int)strlen(cipher);
	if (length != 16)
	{
		printf("--cipher: Value should be 16 char long\n");
		usage(prog_name);
	}

	for (int i = 0; i < 16; i++)
	{
		if (!('0' <= cipher[i] && cipher[i] <= 'f') && !('A' <= cipher[i] && cipher[i] <= 'F'))
		{
			printf("--cipher: Provided cipher alphabet is not correct. Cipher alphabet is: 0123456789abcdefABCDEF\n");
			usage(prog_name);
		}
	}
}

__host__ void parse_runtime_parameters(int argc, char** argv, char** key_alphabet, int* key_length,
                                       char** plaintext_alphabet,
                                       int* plaintext_length, uint64_t* ciphertext, bool* run_cpu, bool* run_gpu)
{
	bool cipher_parameter = false,
		key_alphabet_parameter = false,
		key_length_parameter = false,
		plaintext_alphabet_parameter = false,
		plaintext_length_parameter = false;

	char* cipher_hex = nullptr;
	*run_cpu = false;
	*run_gpu = false;
	*key_length = 8;
	*plaintext_length = 8;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--cpu") == 0)
		{
			*run_cpu = true;
		}
		else if (strcmp(argv[i], "--gpu") == 0)
		{
			*run_gpu = true;
		}
	}

	for (int i = 1; i < argc - 1; i++)
	{
		if (strcmp(argv[i], "--cipher") == 0)
		{
			cipher_hex = argv[i + 1];
			cipher_parameter = true;
		}
		else if (strcmp(argv[i], "--key-alphabet") == 0)
		{
			*key_alphabet = argv[i + 1];
			key_alphabet_parameter = true;
		}
		else if (strcmp(argv[i], "--key-length") == 0)
		{
			(*key_length) = atoi(argv[i + 1]);
			key_length_parameter = true;
		}
		else if (strcmp(argv[i], "--text-alphabet") == 0)
		{
			*plaintext_alphabet = argv[i + 1];
			plaintext_alphabet_parameter = true;
		}
		else if (strcmp(argv[i], "--text-length") == 0)
		{
			(*plaintext_length) = atoi(argv[i + 1]);
			plaintext_length_parameter = true;
		}
	}

	if (!key_alphabet_parameter)
	{
		printf("--key-alphabet: parameter is required\n");
		usage(argv[0]);
	}

	if (!plaintext_alphabet_parameter)
	{
		printf("--text-alphabet: parameter is required\n");
		usage(argv[0]);
	}

	if (!cipher_parameter)
	{
		printf("--cipher: parameter is required\n");
		usage(argv[0]);
	}

	check_cipher(cipher_hex, argv[0]);
	*key_alphabet = transform_key_alphabet(*key_alphabet, argv[0]);
	*plaintext_alphabet = transform_plaintext_alphabet(*plaintext_alphabet, argv[0]);


	if (!key_length_parameter)
	{
		printf("--key-length: using default value [%d]\n", *key_length);
	}
	else
	{
		if (!(1 <= *key_length && *key_length <= 8))
		{
			printf("--key-length: length should be between 1 and 8\n");
			usage(argv[0]);
		}
	}


	if (!plaintext_length_parameter)
	{
		printf("--text-length: using default value [%d]\n", *plaintext_length);
	}
	else
	{
		if (!(1 <= *plaintext_length && *plaintext_length <= 8))
		{
			printf("--text-length: length should be between 1 and 8\n");
			usage(argv[0]);
		}
	}

	*ciphertext = strtoull(cipher_hex, nullptr, 16);

	if (!*run_gpu && !*run_cpu)
	{
		printf("Missing --cpu or --gpu parameter\n");
		usage(argv[0]);
	}
}

__host__ char* transform_key_alphabet(char* key_alphabet, char* prog_name)
{
	if (key_alphabet == nullptr)
	{
		printf("--key-alphabet: Provided alphabet is empty\n");
		usage(prog_name);
	}
	size_t length = strlen(key_alphabet);
	if (length < 2)
	{
		printf("--key-alphabet: Provided alphabet is too short. Min length is 2\n");
		usage(prog_name);
	}

	char* alphabet = new char[length + 1];
	for (int i = 0; i < length; i++)
	{
		alphabet[i] = key_alphabet[i];
	}
	alphabet[length] = '\x00';

	std::sort(alphabet, alphabet + length);
	std::unique(alphabet, alphabet + length + 1);
	length = strlen(alphabet);
	std::unique(alphabet, alphabet + length + 1, [](char a, char b) -> bool
	{
		// des doesn't care about 8th bit in each byte, so we can reduce key-alphabet
		auto a_masked = a & 0xfe;
		auto b_masked = b & 0xfe;

		return a_masked == b_masked;
	});

	return alphabet;
}

__host__ char* transform_plaintext_alphabet(char* plaintext_alphabet, char* prog_name)
{
	if (plaintext_alphabet == nullptr)
	{
		printf("--plaintext_alphabet: Provided alphabet is empty\n");
		usage(prog_name);
	}
	int length = (int)strlen(plaintext_alphabet);
	if (length < 2)
	{
		printf("--plaintext_alphabet: Provided alphabet is too short. Min length is 2\n");
		usage(prog_name);
	}

	char* alphabet = new char[length + 1];
	for (int i = 0; i < length; i++)
	{
		alphabet[i] = plaintext_alphabet[i];
	}
	alphabet[length] = '\x00';

	std::sort(alphabet, alphabet + length);
	std::unique(alphabet, alphabet + length + 1);

	return alphabet;
}

__host__ void print_parameters(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                               const int plaintext_length, const uint64_t cipher, const bool run_cpu,
                               const bool run_gpu)
{
	uint64_t keys_to_check = number_of_combinations(strlen(key_alphabet), key_length),
		plaintexts_to_check = number_of_combinations(strlen(plaintext_alphabet), plaintext_length);

	printf("=== PARAMETERS ===\n");
	printf("Key alphabet:        %s\n", key_alphabet);
	printf("Key length:          %d\n", key_length);
	printf("Plaintext alphabet:  %s\n", plaintext_alphabet);
	printf("Plaintext length:    %d\n", plaintext_length);
	printf("Cipher :             ");
	hex_dump(cipher, true);
	printf("\nKeys to check:       %llu\n", keys_to_check);
	printf("Texts to check:      %llu\n\n", plaintexts_to_check);

	printf("Run cpu version:     %s\n", run_cpu ? "True" : "False");
	printf("Run gpu version:     %s\n\n", run_gpu ? "True" : "False");
}


#pragma endregion
