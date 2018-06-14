#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <cstdint>
#include "des_cracker_cpu.cuh"
#include "des_cracker_gpu.cuh"
#include "runtime_parameters.hpp"

int main(int argc, char** argv)
{
	char* alphabet;
	uint64_t ciphertext;
	int key_length, plaintext_length;
	bool run_cpu;

	//char* a1 = "abcde";
	//uint64_t plaintext1 = init_combinations(a1, 5, 6, 0);
	//for (uint64_t i = 0;i<10;i++)
	//{
	//	print_as_hex(plaintext1);
	//	plaintext1 = next_combination(plaintext1, a1, 5, 1);
	//	printf("\n");
	//	uint64_t plaintext2 = create_combination(i, a1, 5, 6);
	//	print_as_hex(plaintext2);
	//	printf("\n");
	//}

	create_pattern(321654, "abcde", 5, 6);

	parse_runtime_parameters(argc, argv, &alphabet, &ciphertext, &key_length, &plaintext_length, &run_cpu);
	if (run_cpu)
		run_cpu_version(alphabet, key_length, plaintext_length, ciphertext, 100);
	run_gpu_version(alphabet, key_length, plaintext_length, ciphertext, 100);


	return 0;
}