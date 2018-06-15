#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <cstdint>
#include "des_cracker_cpu.cuh"
#include "des_cracker_gpu.cuh"
#include "runtime_parameters.hpp"

int main(int argc, char** argv)
{
	char *key_alphabet,
	     *plaintext_alphabet;
	uint64_t ciphertext;
	int key_length,
	    plaintext_length;
	bool run_cpu;

	parse_runtime_parameters(argc, argv, &key_alphabet, &key_length, &plaintext_alphabet, &plaintext_length, &ciphertext,
	                         &run_cpu);

	print_parameters(key_alphabet, key_length, plaintext_alphabet, plaintext_length, ciphertext, run_cpu);

	run_gpu_version(key_alphabet, key_length, plaintext_alphabet, plaintext_length, ciphertext, 100);
	if (run_cpu)
		run_cpu_version(key_alphabet, key_length, plaintext_alphabet, plaintext_length, ciphertext, 100);

	free(key_alphabet);
	free(plaintext_alphabet);

	return 0;
}
