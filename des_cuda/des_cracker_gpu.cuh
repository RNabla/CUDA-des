#pragma once
#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
#include <stdint.h>
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
                       const uint64_t text_combinations, const uint64_t key_combinations, const uint64_t ciphertext,
                       const int output_limit, uint64_t* const plaintexts, uint64_t* const keys, int* count);

__device__ uint64_t get_warp_id();

__device__ void setup_shared_memory(int* ptr, uint64_t key, const int warps_per_block);

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

__device__ void setup_shared_memory(int* ptr, uint64_t key, const int warps_per_block)
{
	int i = 0;
	int offset = 0;
	for (i = 0; i < 16; i++)
		ptr[offset++] = d_rot[i];
	for (i = 0; i < 56; i++)
		ptr[offset++] = d_pc1[i];
	for (i = 0; i < 48; i++)
		ptr[offset++] = d_pc2[i];
	for (i = 0; i < 64; i++)
		ptr[offset++] = d_ip[i];
	for (i = 0; i < 64; i++)
		ptr[offset++] = d_ip_rev[i];
	for (i = 0; i < 48; i++)
		ptr[offset++] = d_e[i];
	for (i = 0; i < 32; i++)
		ptr[offset++] = d_p[i];
	for (i = 0; i < 512; i++)
		ptr[offset++] = d_s[i];

	//*(uint64_t*)(&ptr[840 + 32 * warps_per_block]) = key;
	*(uint64_t*)(ptr + 968) = key;
}

__global__ void kernel(const char* key_alphabet, const int key_alphabet_length, const int key_length,
                       const char* text_alphabet, const int text_alphabet_length, const int text_length,
                       const uint64_t text_combinations, const uint64_t key_combinations, const uint64_t ciphertext,
                       const int output_limit, uint64_t* const plaintexts, uint64_t* const keys, int* count)
{
	uint64_t warp_id = get_warp_id();
	uint64_t thread_id = threadIdx.x & 0x1f;
	int local_warp_id = threadIdx.x / 32;
	// shared memory layout
	//   name #  rot  |  pc1 |  pc2 |   ip | ip_rev |    e |    p |    s | round_keys |  key  
	//   size #   64  |  224 |  192 |  256 |    256 |  192 |  128 | 2048 |        512 |    8 
	// offset #    0  |   64 |  288 |  480 |    732 |  992 | 1184 | 1312 |       3360 | 3872 


	// rot         int32_t[16]
	// pc1         int32_t[56]
	// pc2         int32_t[48]
	// ip          int32_t[64]
	// ip_rev      int32_t[64]
	// e           int32_t[48[
	// p           int32_t[32]
	// s           int32_t[512]	
	// round_keys  uint64_t[16] {4}
	// key         uint64_t

	__shared__ int cache[
		16 + /* rot */
		56 + /* pc1 */
		48 + /* pc2 */
		64 + /* ip */
		64 + /* ip_rev */
		48 + /* e */
		32 + /* p */
		512 + /* s */
		16 * 2 * 4 + /* round keys (16 keys * 2 sizeof int * 4 warps) */
		2 /* key */
	];
	const int warps_per_block = 4;
	if (warp_id < key_combinations)
	{
		
		uint64_t key = create_pattern(warp_id, key_alphabet, key_alphabet_length, key_length);
		uint64_t* round_keys = (uint64_t*)(cache + 840 + local_warp_id * 32);
		if (thread_id == 0)
		{
			setup_shared_memory(cache, key, warps_per_block);
			generate_round_keys(key, round_keys, cache, cache + 16, cache + 72);
			//*(uint64_t*)(cache + 968) = key;
			//uint64_t from_cache = *(uint64_t*)(cache + 968);
			//if (from_cache != key)
			//	printf("key is %llu and in shared is %llu\n", key, *(uint64_t*)(cache + 968));
		}
		for (uint64_t i = thread_id; i < text_combinations; i += 32)
		{
			uint64_t plaintext = create_pattern(i, text_alphabet, text_alphabet_length, text_length);
			if (ciphertext == des_encrypt(plaintext, round_keys, cache + 120, cache + 184, cache + 248, cache + 296,
			                              cache + 328))
			{
				int index = atomicAdd(count, 1);
				if (index < output_limit)
				{
					//keys[index] = *(uint64_t*)(cache + 968);
					keys[index] = key;
					plaintexts[index] = plaintext;
				}
			}
		}
	}
}

__host__ void run_gpu_version(const char* key_alphabet, const int key_length, const char* plaintext_alphabet,
                              const int plaintext_length, const uint64_t ciphertext,
                              const int output_limit)
{
	float kernel_elapsed_time = -1;
	char *d_key_alphabet,
	     *d_plaintext_alphabet;
	int *d_count,
	    h_count;
	uint64_t *d_plaintexts,
	         *d_keys,
	         *h_plaintexts = new uint64_t[output_limit],
	         *h_keys = new uint64_t[output_limit];

	const int32_t key_alphabet_length = (int32_t)strlen(key_alphabet);
	const int32_t plaintext_alphabet_length = (int32_t)strlen(plaintext_alphabet);

	cudaEvent_t kernel_start,
	            kernel_stop;

	dim3 threads_per_block,
	     blocks;

	std::chrono::steady_clock::time_point gpu_start, gpu_end;

	printf("=== GPU ===\n");

	gpu_start = std::chrono::high_resolution_clock::now();
	gpuErrchk(cudaDeviceSetLimit(cudaLimitMallocHeapSize, 128 * 1024 * 1024));
	gpuErrchk(cudaSetDevice(0));
	gpuErrchk(cudaEventCreate(&kernel_start));
	gpuErrchk(cudaEventCreate(&kernel_stop));
	gpuErrchk(cudaMalloc(&d_key_alphabet, key_alphabet_length));
	gpuErrchk(cudaMalloc(&d_plaintext_alphabet, plaintext_alphabet_length));
	gpuErrchk(cudaMemcpy(d_key_alphabet, key_alphabet, key_alphabet_length, cudaMemcpyHostToDevice));
	gpuErrchk(cudaMemcpy(d_plaintext_alphabet, plaintext_alphabet, plaintext_alphabet_length, cudaMemcpyHostToDevice));
	gpuErrchk(cudaMalloc(&d_count, sizeof(int)));
	gpuErrchk(cudaMalloc(&d_plaintexts, output_limit * sizeof(uint64_t)));
	gpuErrchk(cudaMalloc(&d_keys, output_limit * sizeof(uint64_t)));
	gpuErrchk(cudaMemset(d_count, 0, sizeof(int)));
	gpuErrchk(cudaMemset(d_keys, 0, sizeof(uint64_t) * output_limit));
	gpuErrchk(cudaMemset(d_plaintexts, 0, sizeof(uint64_t) * output_limit));

	uint64_t keys_to_check = number_of_combinations(key_alphabet_length, key_length);
	uint64_t plaintexts_to_check = number_of_combinations(plaintext_alphabet_length, plaintext_length);
	uint64_t threads_needed = keys_to_check * 32;
	if (!calculate_distribution(threads_needed, &threads_per_block, &blocks))
	{
		printf("Couldn't create suitable grid");
		return;
	}
	printf("[DEBUG - GPU] threads needed:    %d\n", threads_needed);
	printf("[DEBUG - GPU] threads per block: %d\n", threads_per_block.x);
	printf("[DEBUG - GPU] block_x: %d block_y %d block_z %d\n", blocks.x, blocks.y, blocks.z);

	gpuErrchk(cudaEventRecord(kernel_start));
	gpuErrchk(cudaGetLastError());

	kernel <<<blocks, threads_per_block >>>(
		d_key_alphabet,
		key_alphabet_length,
		key_length,
		d_plaintext_alphabet,
		plaintext_alphabet_length,
		plaintext_length,
		plaintexts_to_check,
		keys_to_check,
		ciphertext,
		output_limit,
		d_plaintexts,
		d_keys,
		d_count
	);

	gpuErrchk(cudaGetLastError());
	gpuErrchk(cudaDeviceSynchronize());
	gpuErrchk(cudaGetLastError());
	gpuErrchk(cudaEventRecord(kernel_stop));
	gpuErrchk(cudaEventSynchronize(kernel_stop));
	gpuErrchk(cudaEventElapsedTime(&kernel_elapsed_time, kernel_start, kernel_stop));

	gpuErrchk(cudaMemcpy(h_keys, d_keys, sizeof(uint64_t) * output_limit, cudaMemcpyDeviceToHost));
	gpuErrchk(cudaMemcpy(h_plaintexts, d_plaintexts, sizeof(uint64_t) * output_limit, cudaMemcpyDeviceToHost));
	gpuErrchk(cudaMemcpy(&h_count, d_count, sizeof(int), cudaMemcpyDeviceToHost));
	gpuErrchk(cudaDeviceSynchronize());

	gpuErrchk(cudaFree(d_key_alphabet));
	gpuErrchk(cudaFree(d_plaintext_alphabet));
	gpuErrchk(cudaFree(d_count));
	gpuErrchk(cudaFree(d_keys));
	gpuErrchk(cudaFree(d_plaintexts));
	gpuErrchk(cudaEventDestroy(kernel_start));
	gpuErrchk(cudaEventDestroy(kernel_stop));
	gpu_end = std::chrono::high_resolution_clock::now();
	show_results(h_keys, h_plaintexts, h_count, output_limit);

	printf("GPU time (all)             [ms]: %llu\n",
	       std::chrono::duration_cast<std::chrono::milliseconds>(gpu_end - gpu_start).count());
	if (kernel_elapsed_time >= 0.0)
		printf("GPU time (kernel)          [ms]: %llu\n", (unsigned long long)kernel_elapsed_time);

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
