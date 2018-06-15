#pragma once

#include "string"

void usage(char* name);

void check_alphabet(char* alphabet, char* prog_name);

void check_cipher(char* cipher, char* prog_name);

void parse_runtime_parameters(int argc, char** argv, char** alphabet, uint64_t* ciphertext, int* key_length,
                              int* plaintext_length, bool* run_cpu);

void parse_runtime_parameters(int argc, char** argv, char** key_alphabet, int* key_length, char** plaintext_alphabet,
	int* plaintext_length, uint64_t* ciphertext, bool* run_cpu);

char* transform_key_alphabet(char* key_alphabet, char* prog_name);

char* transform_plaintext_alphabet(char* plaintext_alphabet, char* prog_name);

void print_parameters(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                      const int plaintext_length, const uint64_t cipher, const bool run_cpu);
