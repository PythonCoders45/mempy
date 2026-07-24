#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define CACHE_LINE_SIZE 64
#define DEFAULT_SLAB_SIZE (1024 * 1024) // 1MB per thread slab

// Metadata chunk preceding every memory allocation block
typedef struct ChunkHeader {
    size_t size;
    bool is_free;
    struct ChunkHeader *next;
    uint8_t padding[47]; // Pad structure to exactly 64 bytes for cache alignment
} ChunkHeader;

// Thread-Local Arena structure
typedef struct ThreadArena {
    uint8_t *raw_buffer;
    size_t capacity;
    size_t offset;
    ChunkHeader *free_list;
    uint64_t total_allocations;
    uint64_t total_frees;
} ThreadArena;

// Public API
void memguard_init_thread_arena(size_t slab_size);
void* memguard_thread_alloc(size_t size);
void memguard_thread_free(void* ptr);
void memguard_destroy_thread_arena(void);

#endif // THREAD_POOL_H
