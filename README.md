# CUDA-des
Bruteforcing DES using CUDA

Bruteforce attack is just simple lookup on every possible key and plaintext based on provided alphabet and key/plaintext length. If length is shorter than 8 then null-pading is applied (non used bytes are replaced with \x00). Program uses CUDA technology to speed-up bruteforce attack simple by checking each key and every possible plaintext using exactly one warp 

# Runtime parameters
--cipher : Hexencoded cipher to match against  
--key-alphabet : Alphabet of the possible chars in key  
--key-length : Length of the key to brute  
--text-alphabet : Alphabet of the possible chars in plaintext  
--text-length : Length of the plaintext to brute  
--cpu : Run CPU version  
--gpu : Run GPU version  
  


# Makefile
Add your specific platform to Makefile like  
-gencode arch=compute_XX,code=compute_XX -gencode arch=compute_XX,sm=compute_XX

# Technical limits
If you are using for example compute compatibility 3.0 please change *warps_per_block* constant in *des_cracker_gpu (line:3)* to 4 so that you can achieve more occupancy by lower shared memory usage (exactly 4096 bytes)  
Alphabet is limited to 24 characters (reason is above)  
DES uses only 7 bits in every byte (this concerns only key), so for example 'b' and 'c' is the same (ignoring parity correctness), so program can lower key alphabet space to produce results faster  

# Simple usage
./des-cracker --cipher d018aaea04f5b93b --text-alphabet abcdef --key-alphabet ab --gpu  
--key-length: using default value [8]  
--text-length: using default value [8]  
=== PARAMETERS ===  
Key alphabet:        ab  
Key length:          8  
Plaintext alphabet:  abcdef  
Plaintext length:    8  
Cipher :             d0 18 aa ea 04 f5 b9 3b  | .......;  
  
Keys to check:       256  
Texts to check:      1679616  
  
Run cpu version:     False  
Run gpu version:     True  
  
=== GPU ===  
Results:  
0 # Key: 61 62 62 61 62 62 61 62  | abbabbab    Plaintext: 61 62 63 64 61 62 63 61  | abcdabca  
  
GPU time (all)             [ms]: 14013  
GPU time (kernel)          [ms]: 11176  
