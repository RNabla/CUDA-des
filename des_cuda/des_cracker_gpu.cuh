#pragma once
#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
#define warps_per_block (8)
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

__global__ void kernel(const char* key_alphabet, const char* text_alphabet, const uint32_t lengths,
                       const uint32_t text_combinations, const uint32_t key_combinations, const uint64_t ciphertext,
                       const int output_limit, uint64_t* const plaintexts, uint64_t* const keys, int* count);

__device__ uint32_t get_warp_id();

__host__ bool calculate_distribution(uint64_t threads_needed, dim3* threads_per_block, dim3* blocks);

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

#define key_alphabet_length (lengths >> 24)
#define key_length ((lengths >> 16) & 0xff)
#define text_alphabet_length ((lengths >> 8) & 0xff)
#define text_length (lengths & 0xff)
#define round_keys_gen ((uint64_t*)(cache + 840 + thread_id * 32))
#define round_keys ((uint64_t*)(cache + 840 + local_warp_id * 32))
#define warp_id (get_warp_id())
#define key_gen ((uint64_t*)(cache + 840 + 32 * warps_per_block + thread_id * 2))
#define key_res ((uint64_t*)(cache + 840 + 32 * warps_per_block + local_warp_id * 2))
//#define key_res ((uint64_t*)(cache+968+local_warp_id*2))
#define thread_id (threadIdx.x & 0x1f)
#define local_warp_id (threadIdx.x / 32)
#define rot (cache)
#define pc1 (cache+16)
#define pc2 (cache+72)
#define ip (cache+120)
#define ip_rev (cache+184)
#define e (cache+248)
#define p (cache+296)
#define s (cache+328)
#define key_alphabet_sm (cache + 840 + 34 * warps_per_block)
#define text_alphabet_sm (cache + 840 + 34 * warps_per_block + 32)
__global__ void kernel(const char* key_alphabet, const char* text_alphabet, const uint32_t lengths,
                       const uint32_t text_combinations, const uint32_t key_combinations, const uint64_t ciphertext,
                       const int output_limit, uint64_t* const plaintexts, uint64_t* const keys, int* count)
{
#pragma region doc

	// lengths layout
	// key_alphabet_length | key_length | text_alphabet_length | text_length

	// shared memory layout (for warps_per_block := 4)
	//   name #  rot  |  pc1 |  pc2 |   ip | ip_rev |    e |    p |    s | round_keys |     key | key_alphabet | text_alphabet
	//   size #   64  |  224 |  192 |  256 |    256 |  192 |  128 | 2048 |     varies |  varies |          128 |           128
	// offset #    0  |   64 |  288 |  480 |    732 |  992 | 1184 | 1312 |     varies |  varies |       varies |        varies

	// rot           int32_t[16]
	// pc1           int32_t[56]
	// pc2           int32_t[48]
	// ip            int32_t[64]
	// ip_rev        int32_t[64]
	// e             int32_t[48[
	// p             int32_t[32]
	// s             int32_t[512]	
	// round_keys    uint64_t[16] x {warps_per_block}
	// key           uint64_t x {warps_per_block}
	// key_alphabet  int32_t[24] 
	// text_alphabet int32_t[24] 
#pragma endregion

	__shared__ int cache[
		16 + /* rot */
		56 + /* pc1 */
		48 + /* pc2 */
		64 + /* ip */
		64 + /* ip_rev */
		48 + /* e */
		32 + /* p */
		512 + /* s */
		16 * 2 * warps_per_block + /* round keys (16 keys * 2 sizeof int) */
		2 * warps_per_block + /* master keys (2 * sizeof int) */
		2 * 24 /* alphabets */
	];
	if (warp_id < key_combinations)
	{
		if (local_warp_id == 0)
		{
			for (int i = threadIdx.x; i < 840; i += 32)
				cache[i] = d_constants[i];

			if (threadIdx.x < key_alphabet_length)
			{
				key_alphabet_sm[threadIdx.x] = key_alphabet[threadIdx.x];
			}

			if (threadIdx.x < text_alphabet_length)
			{
				text_alphabet_sm[threadIdx.x] = text_alphabet[threadIdx.x];
			}

			if (thread_id < warps_per_block)
			{
				*key_gen = create_pattern(warp_id + thread_id, key_alphabet_sm, key_alphabet_length, key_length);
				generate_round_keys(*key_gen, round_keys_gen, rot, pc1, pc2);
			}
		}
		__syncthreads();
		for (uint32_t i = thread_id; i < text_combinations; i += 32)
		{
			uint64_t plaintext = create_pattern(i, text_alphabet_sm, text_alphabet_length, text_length);
			if (ciphertext == des_encrypt(plaintext, round_keys, ip, ip_rev, e, p, s))
			{
				int index = atomicAdd(count, 1);
				if (index < output_limit)
				{
					keys[index] = *key_res;
					plaintexts[index] = plaintext;
				}
			}
		}
	}
}

#undef key_alphabet_length
#undef key_length
#undef text_alphabet_length
#undef text_length
#undef round_keys
#undef round_keys_gen
#undef key_gen
#undef key_res
#undef warp_id
#undef thread_id
#undef local_warp_id
#undef rot
#undef pc1
#undef pc2
#undef ip
#undef ip_rev
#undef e
#undef p
#undef s
#undef key_alphabet_sm
#undef text_alphabet_sm

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
#ifdef _DEBUG
	printf("[DEBUG - GPU] threads needed:    %llu\n", threads_needed);
	printf("[DEBUG - GPU] threads per block: %d\n", threads_per_block.x);
	printf("[DEBUG - GPU] block_x: %d block_y %d block_z %d\n", blocks.x, blocks.y, blocks.z);
#endif

	gpuErrchk(cudaEventRecord(kernel_start));
	gpuErrchk(cudaGetLastError());


	uint32_t lengths = (key_alphabet_length << 24) | (key_length << 16) | (plaintext_alphabet_length << 8) |
		plaintext_length;

	kernel << <blocks, threads_per_block >> >(
		d_key_alphabet,
		d_plaintext_alphabet,
		lengths,
		plaintexts_to_check,
		keys_to_check,
		ciphertext,
		output_limit,
		d_plaintexts,
		d_keys,
		d_count
	);

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


__device__ uint32_t get_warp_id()
{
	uint32_t blockId = blockIdx.x
		+ blockIdx.y * gridDim.x
		+ gridDim.x * gridDim.y * blockIdx.z;
	return (blockId * blockDim.x + threadIdx.x) / (uint32_t)32;
}

__host__ bool calculate_distribution(uint64_t threads_needed, dim3* threads_per_block, dim3* blocks)
{
	const uint32_t threads_in_block = (uint32_t)(threads_needed >= 32L * warps_per_block
		                                             ? 32L * warps_per_block
		                                             : threads_needed);
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
