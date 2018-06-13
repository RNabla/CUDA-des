#include "runtime_parameters.hpp"


void usage(char* name)
{
	printf("%s - CUDA DES Cracker - Andrzej Nowikowski - 2018\n", name);
	printf("Usage: \n");
	printf("%s --alphabet <alphabet> --cipher <hex> [--key-length <length>] [--text-length <length>] [--cpu]\n\n", name);
	printf("    --alphabet <alphabet> \t Alphabet to work with. Should be ordered ascending and compact\n");
	printf("    --cipher <hex> \t\t Hexencoded cipher to match against\n");
	printf("    --key-length <length=8> \t Length of the key to brute. Length should be between 1 and 8\n");
	printf("    --text-length <length=8> \t Length of the plaintext to brute. Length should be between 1 and 8\n");
	printf("    --cpu \t\t\t Try run CPU version of cracker\n");
	exit(1);
}

void check_alphabet(char* alphabet, char* prog_name)
{
	if (alphabet == nullptr)
	{
		printf("--alphabet: Provided alphabet is empty\n");
		usage(prog_name);
	}
	int length = (int)strlen(alphabet);
	if (length < 2)
	{
		printf("--alphabet: Provided alphabet is too short. Min length is 2\n");
		usage(prog_name);
	}

	for (int i = 1; i < length - 1; i++)
	{
		if (alphabet[i + 1] - alphabet[i] != 1)
		{
			printf("--alphabet: Provided alphabet is not compact. Distance between %c and %c is %d, should be 1.\n", alphabet[i],
			       alphabet[i + 1], alphabet[i + 1] - alphabet[i]);
			usage(prog_name);
		}
	}
}

void check_cipher(char* cipher, char* prog_name)
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

void parse_runtime_parameters(int argc, char** argv, char** alphabet, uint64_t* ciphertext, int* key_length,
                              int* plaintext_length, bool* run_cpu)
{
	bool alphabet_parameter = false,
		cipher_parameter = false,
		key_length_parameter = false,
		plaintext_length_parameter = false;

	char* cipher_hex = nullptr;
	*run_cpu = false;
	*key_length = 8;
	*plaintext_length = 8;


	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--cpu") == 0)
		{
			*run_cpu = true;
		}
	}

	for (int i = 1; i < argc - 1; i++)
	{
		
		if (strcmp(argv[i], "--alphabet") == 0)
		{
			*alphabet = argv[i + 1];
			alphabet_parameter = true;
		}
		else if (strcmp(argv[i], "--cipher") == 0)
		{
			cipher_hex = argv[i + 1];
			cipher_parameter = true;
		}
		else if (strcmp(argv[i], "--key-length") == 0)
		{
			(*key_length) = atoi(argv[i + 1]);
			key_length_parameter = true;
		}
		else if (strcmp(argv[i], "--text-length") == 0)
		{
			(*plaintext_length) = atoi(argv[i + 1]);
			plaintext_length_parameter = true;
		}
	}

	if (!alphabet_parameter)
	{
		printf("--alphabet: parameter is required\n");
		usage(argv[0]);
	}

	if (!cipher_parameter)
	{
		printf("--cipher: parameter is required\n");
		usage(argv[0]);
	}

	check_alphabet(*alphabet, argv[0]);
	check_cipher(cipher_hex, argv[0]);

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
}
