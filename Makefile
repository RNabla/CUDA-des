all:
	nvcc -O3 -std=c++11 ./src/kernel.cu -o des-cracker
