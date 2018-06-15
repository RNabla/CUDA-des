#pragma once
#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
#include <cstdint>
#include <cstring>
#include <cmath>
#include "misc.cuh"
#include "des.cuh"

#pragma region headers

__host__ void run_gpu_version(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                              const int plaintext_length, const uint64_t ciphertext,
                              const int output_limit);

__host__ void gpuAssert(cudaError_t code, const char* file, int line, bool abort = true);

__global__ void kernel(const char* key_alphabet, const int key_alphabet_length, const int key_length,
                       const char* text_alphabet, const int text_alphabet_length, const int text_length,
                       const uint64_t text_combinations,
                       const uint64_t ciphertext, const int output_limit, uint64_t* const plaintexts,
                       uint64_t* const keys, int* count);

__device__ uint64_t get_warp_id();

__host__ bool calculate_distribution(uint64_t threads_needed, dim3* threads_per_block, dim3* blocks)
{
	const uint32_t threads_in_block = (uint32_t)(threads_needed >= 128L ? 128L : threads_needed);
	uint64_t blocks_needed = (long)ceilf(threads_needed / (float)threads_in_block);
	const uint32_t block_x = (uint32_t)(blocks_needed >= 1024L ? 1024L : blocks_needed);
	blocks_needed = (int)ceilf(blocks_needed / (float)block_x);
	const uint32_t block_y = (uint32_t)(blocks_needed >= 1024L ? 1024L : blocks_needed);
	blocks_needed = (int)ceilf(blocks_needed / (float)block_y);
	if (blocks_needed >= 64L)
		return false;
	const uint32_t block_z = (uint32_t)blocks_needed;

	threads_per_block->x = threads_in_block;
	threads_per_block->y = 1;
	threads_per_block->z = 1;

	blocks->x = block_x;
	blocks->y = block_y;
	blocks->z = block_z;

	return true;
}

#pragma endregion

#pragma region implementation

__host__ void gpuAssert(cudaError_t code, const char* file, int line, bool abort)
{
	if (code != cudaSuccess)
	{
		fprintf(stderr, "GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
		if (abort) exit(code);
	}
}

__global__ void kernel(const char* key_alphabet, const int key_alphabet_length, const int key_length,
                       const char* text_alphabet, const int text_alphabet_length, const int text_length,
                       const uint64_t text_combinations,
                       const uint64_t ciphertext, const int output_limit, uint64_t* const plaintexts,
                       uint64_t* const keys, int* count)
{
	uint64_t warp_id = get_warp_id();
	uint64_t round_keys[16];
	uint64_t key = create_pattern(warp_id, key_alphabet, key_alphabet_length, key_length);
	generate_round_keys(key, round_keys);
	for (uint64_t j = threadIdx.x & 0x1fULL; j < text_combinations; j += 32)
	{
		uint64_t plaintext = create_pattern(j, text_alphabet, text_alphabet_length, text_length);
		if (ciphertext == des_encrypt(plaintext, round_keys))
		{
			int index = atomicAdd(count, 1);
			if (index < output_limit)
			{
				keys[index] = key;
				plaintexts[index] = plaintext;
			}
		}
	}
}

__host__ void run_gpu_version(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                              const int plaintext_length, const uint64_t ciphertext,
                              const int output_limit)
{
	float elapsed_time = -1;
	char *d_key_alphabet,
	     *d_plaintext_alphabet;
	int *d_count,
	    h_count;
	uint64_t *d_plaintexts,
	         *d_keys,
	         *h_plaintexts = new uint64_t[output_limit],
	         *h_keys = new uint64_t[output_limit];

	const size_t key_alphabet_length = strlen(key_alphabet);
	const size_t plaintext_alphabet_length = strlen(plaintext_alphabet);

	cudaEvent_t kernel_start,
	            kernel_stop;

	dim3 threads_per_block,
	     blocks;

	gpuErrchk(cudaSetDevice(0));
	//gpuErrchk(cudaEventCreate(&kernel_start));
	//gpuErrchk(cudaEventCreate(&kernel_stop));
	gpuErrchk(cudaMalloc(&d_key_alphabet, key_alphabet_length));
	gpuErrchk(cudaMalloc(&d_plaintext_alphabet, plaintext_alphabet_length));
	gpuErrchk(cudaMemcpy(d_key_alphabet, key_alphabet, key_alphabet_length, cudaMemcpyHostToDevice));
	gpuErrchk(cudaMemcpy(d_plaintext_alphabet, plaintext_alphabet, plaintext_alphabet_length, cudaMemcpyHostToDevice));
	gpuErrchk(cudaMalloc(&d_count, sizeof(int)));
	gpuErrchk(cudaMalloc(&d_plaintexts, output_limit * sizeof(uint64_t)));
	gpuErrchk(cudaMalloc(&d_keys, output_limit * sizeof(uint64_t)));
	gpuErrchk(cudaMemset(d_count, 0, sizeof(int)));
	//gpuErrchk(cudaMemset(d_keys, 0, sizeof(uint64_t) * output_limit));
	//gpuErrchk(cudaMemset(d_plaintexts, 0, sizeof(uint64_t) * output_limit));
	//gpuErrchk(cudaEventRecord(kernel_start));

	uint64_t keys_to_check = number_of_combinations(key_alphabet_length, key_length);
	calculate_distribution(keys_to_check * 32, &threads_per_block, &blocks);
	printf("[DEBUG - GPU] keys to check: %d\n", keys_to_check);
	printf("[DEBUG - GPU] threads per block: %d\n", threads_per_block.x);
	printf("[DEBUG - GPU] block_x: %d block_y %d block_z %d\n", blocks.x, blocks.y, blocks.z);

	kernel << <blocks, threads_per_block >> >(
		d_key_alphabet,
		key_alphabet_length,
		key_length,
		d_plaintext_alphabet,
		plaintext_alphabet_length,
		plaintext_length,
		number_of_combinations(plaintext_alphabet_length, plaintext_length),
		ciphertext,
		output_limit,
		d_plaintexts,
		d_keys,
		d_count
	);

	gpuErrchk(cudaGetLastError());
	//gpuErrchk(cudaEventRecord(kernel_stop));
	//gpuErrchk(cudaEventSynchronize(kernel_stop));
	//gpuErrchk(cudaEventElapsedTime(&elapsed_time, kernel_start, kernel_stop));
	//gpuErrchk(cudaEventDestroy(kernel_start));
	//gpuErrchk(cudaEventDestroy(kernel_stop));

	gpuErrchk(cudaMemcpy(h_keys, d_keys, sizeof(uint64_t) * output_limit, cudaMemcpyDeviceToHost));
	gpuErrchk(cudaMemcpy(h_plaintexts, d_plaintexts, sizeof(uint64_t) * output_limit, cudaMemcpyDeviceToHost));
	gpuErrchk(cudaMemcpy(&h_count, d_count, sizeof(int), cudaMemcpyDeviceToHost));

	gpuErrchk(cudaDeviceSynchronize());

	printf("[GPU] Elapsed time: %lf\n", elapsed_time);

	show_results(h_keys, h_plaintexts, h_count, output_limit);

	delete[]h_plaintexts;
	delete[]h_keys;
}


__device__ uint64_t get_warp_id()
{
	uint64_t blockId = blockIdx.x
		+ blockIdx.y * gridDim.x
		+ gridDim.x * gridDim.y * blockIdx.z;
	return (blockId * blockDim.x + threadIdx.x) / (uint64_t)32;
}

#pragma endregion
