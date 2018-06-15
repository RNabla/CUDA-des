#include "misc.hpp"
#include <cstdio>

void hex_dump(const uint64_t value, const bool flush, const int length, const int group)
{
	const char* hex = "0123456789abcdef";
	int counter = 0;
	for (int i = length; --i >= 0;)
	{
		int c = (value & (0xfULL << i * 4)) >> i * 4;
		printf("%c", hex[c]);
		if (++counter % group == 0)
			printf(" ");
	}
	printf(" | ");
	for (int i = length / 2; --i >= 0;)
	{
		int c = (value & (0xffULL << i * 8)) >> i * 8;
		if (32 <= c && c <= 126)
			printf("%c", (char)c);
		else
			printf(".");
	}
	if (flush)
		printf("\n");
}


void show_results(const uint64_t* const keys, const uint64_t* const plaintexts, const int count,
                  const int output_limit)
{
	if (count <= 0)
	{
		printf("No results found\n");
		return;
	}
	printf("Results: \n");
	int limit = count;
	if (limit > output_limit)
		limit = output_limit;
	for (int i = 0; i < limit; i++)
	{
		printf("%d # Key: ", i);
		hex_dump(keys[i]);
		printf("\tPlaintext: ");
		hex_dump(plaintexts[i]);
		printf("\n");
	}
	if (output_limit < count)
	{
		printf("\tAnd %d more matches...", count - output_limit);
	}
	printf("\n");
}
