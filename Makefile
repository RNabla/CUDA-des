all:
	nvcc -O3 ./src/kernel.cu -o des-cracker
