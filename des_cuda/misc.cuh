#pragma once

#include <cstdint>

#pragma region headers


__host__ __device__ uint64_t next_combination(uint64_t value, const char* alphabet, const int alphabet_length,
                                              const uint64_t offset);

__host__ __device__ uint64_t init_combinations(const char* alphabet, const int alphabet_length,
                                               const int segment_length,
                                               const uint64_t offset_from_start);

__host__ __device__ uint64_t create_pattern(uint64_t combination_number, const char* alphabet, int32_t alphabet_length, int32_t segment_length)
{
	int limit = 8 - segment_length;
	uint64_t acc = 0;
	for (int i = 8; --i >= limit;)
	{
		uint64_t y = combination_number / alphabet_length;
		acc *= (1ULL << 8);
		acc += alphabet[combination_number - y * alphabet_length];
		combination_number = y;
	}
	acc *= (1ULL << (8 * limit));
	return acc;
}

__host__ __device__ uint64_t number_of_combinations(const int alphabet_length, int segment_length);


__host__ __device__  void print_as_hex(const uint64_t value, const int length = 16, const int group = 2);

__host__ void show_results(const uint64_t* const keys, const uint64_t* const plaintexts, const int count,
                           const int output_limit);

#pragma endregion

#pragma region implementation

__host__ __device__ uint64_t next_combination(uint64_t value, const char* alphabet, const int alphabet_length,
                                              const uint64_t offset)
{
	const char min_char = alphabet[0];
	char* arr = (char*)&value;
	uint64_t carry = offset;

	int i = 7;
	while (carry > 0 && i >= 0)
	{
		uint64_t x = arr[i] + carry - min_char;
		carry = x / alphabet_length;
		arr[i] = min_char + x % alphabet_length;
		i--;
	}
	return value;
}

__host__ __device__ uint64_t init_combinations(const char* alphabet, const int alphabet_length,
                                               const int segment_length,
                                               const uint64_t offset_from_start)
{
	const char min_char = alphabet[0];
	uint64_t result = 0;
	char* arr = (char*)&result;
	int limit = 8 - segment_length;
	for (int i = 8; --i >= limit;)
		arr[i] = min_char;

	return next_combination(result, alphabet, alphabet_length, offset_from_start);
}

__host__ __device__ uint64_t number_of_combinations(const int alphabet_length, int segment_length)
{
	uint64_t result = 1;
	while (segment_length--)
		result *= alphabet_length;
	return result;
}

__device__  const char* d_hex = "0123456789abcdef";
const char* h_hex = "0123456789abcdef";


__host__ __device__ void print_as_hex(const uint64_t value, const int length, const int group)
{
	int counter = 0;
#if __CUDA_ARCH__
	const char* hex = d_hex;
#else
	const char* hex = h_hex;
#endif
	for (int i = length; --i >= 0;)
	{
		int c = (value & (0xfULL << i * 4)) >> i * 4;
		printf("%c", hex[c]);
		if (++counter % group == 0)
			printf(" ");
	}
}


__host__ void show_results(const uint64_t* const keys, const uint64_t* const plaintexts, const int count,
                           const int output_limit)
{
	if (count <= 0)
	{
		printf("No results found\n");
		return;
	}
	printf("======\n");
	int limit = count;
	if (limit > output_limit)
		limit = output_limit;
	for (int i = 0; i < limit; i++)
	{
		printf("%d # Key: ", i);
		print_as_hex(keys[i]);
		printf("\tPlaintext: ");
		print_as_hex(plaintexts[i]);
		printf("\n");
	}
	if (output_limit < count)
	{
		printf("\tAnd %d more matches...", count - output_limit);
	}
	printf("======\n");
}


#pragma endregion
