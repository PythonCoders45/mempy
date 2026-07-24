#ifndef CRYPTO_SIMD_H
#define CRYPTO_SIMD_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint64_t hash_low;
    uint64_t hash_high;
    size_t bytes_scanned;
} SIMDHashResult;

// Public API
SIMDHashResult simd_fast_hash(const void *data, size_t len);
bool simd_memory_compare(const void *ptr1, const void *ptr2, size_t len);

#endif // CRYPTO_SIMD_H
