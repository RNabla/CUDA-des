#pragma once

#include "string"

void usage(char* name);

void check_alphabet(char* alphabet, char* prog_name);

void check_cipher(char* cipher, char* prog_name);

void parse_runtime_parameters(int argc, char** argv, char** alphabet, uint64_t* ciphertext, int* key_length,
                              int* plaintext_length, bool* run_cpu);
