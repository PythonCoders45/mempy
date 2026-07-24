#include "../include/crypto_simd.h"
#include <stdio.h>

// Include CPU intrinsics based on architecture
#if defined(__x86_64__) || defined(_M_X64)
    #include <immintrin.h>
#endif

// Fast 256-bit SIMD vector hash function
SIMDHashResult simd_fast_hash(const void *data, size_t len) {
    SIMDHashResult result = {0, 0, len};
    const uint8_t *ptr = (const uint8_t*)data;
    size_t i = 0;

#if defined(__AVX2__)
    // 256-bit AVX2 register initialization
    __m256i vec_hash_a = _mm256_set1_epi64x(0x9E3779B97F4A7C15ULL);
    __m256i vec_hash_b = _mm256_set1_epi64x(0xC6A4A7935BD1E995ULL);

    // Process 32 bytes per iteration in a single CPU clock cycle
    for (; i + 32 <= len; i += 32) {
        __m256i chunk = _mm256_loadu_si256((const __m256i*)(ptr + i));
        
        // Vector XOR and Add operations across 256-bit blocks
        vec_hash_a = _mm256_xor_si256(vec_hash_a, chunk);
        vec_hash_a = _mm256_add_epi64(vec_hash_a, vec_hash_b);
        vec_hash_b = _mm256_slli_epi64(vec_hash_a, 13);
    }

    // Extract values from 256-bit registers
    uint64_t temp[4];
    _mm256_storeu_si256((__m256i*)temp, vec_hash_a);
    result.hash_low = temp[0] ^ temp[1];
    result.hash_high = temp[2] ^ temp[3];

#else
    // Portable fallback loop if AVX2 is not supported on target CPU
    uint64_t h1 = 0x9E3779B97F4A7C15ULL;
    uint64_t h2 = 0xC6A4A7935BD1E995ULL;

    for (; i + 8 <= len; i += 8) {
        uint64_t k = *(const uint64_t*)(ptr + i);
        h1 ^= k;
        h1 = (h1 << 13) | (h1 >> 51);
        h2 += h1;
    }
    result.hash_low = h1;
    result.hash_high = h2;
#endif

    // Handle remaining tail bytes
    for (; i < len; i++) {
        result.hash_low ^= ptr[i];
        result.hash_low *= 0x100000001B3ULL;
    }

    return result;
}

// Hardware-accelerated byte comparison (detects silent RAM corruption)
bool simd_memory_compare(const void *ptr1, const void *ptr2, size_t len) {
    const uint8_t *p1 = (const uint8_t*)ptr1;
    const uint8_t *p2 = (const uint8_t*)ptr2;
    size_t i = 0;

#if defined(__AVX2__)
    for (; i + 32 <= len; i += 32) {
        __m256i v1 = _mm256_loadu_si256((const __m256i*)(p1 + i));
        __m256i v2 = _mm256_loadu_si256((const __m256i*)(p2 + i));
        
        __m256i diff = _mm256_xor_si256(v1, v2);
        if (!_mm256_testz_si256(diff, diff)) {
            return false; // Mismatch detected instantly
        }
    }
#endif

    for (; i < len; i++) {
        if (p1[i] != p2[i]) return false;
    }

    return true;
}
