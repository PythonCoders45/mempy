#include "../include/thread_pool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
    #include <windows.h>
    #define TLS_VAR __declspec(thread)
#else
    #include <pthread.h>
    #define TLS_VAR _Thread_local
#endif

// Every OS thread gets its own isolated instance of ThreadArena in TLS
static TLS_VAR ThreadArena* t_local_arena = NULL;

// Round up any byte size to the nearest multiple of 64 bytes
static inline size_t align_to_cache(size_t size) {
    return (size + (CACHE_LINE_SIZE - 1)) & ~(CACHE_LINE_SIZE - 1);
}

void memguard_init_thread_arena(size_t slab_size) {
    if (t_local_arena != NULL) return; // Already initialized for this thread

    size_t alloc_size = slab_size > 0 ? slab_size : DEFAULT_SLAB_SIZE;
    
    // Allocate local thread arena header
    t_local_arena = (ThreadArena*)malloc(sizeof(ThreadArena));
    if (!t_local_arena) return;

    // Allocate continuous physical RAM aligned to CPU cache lines
#if defined(_WIN32)
    t_local_arena->raw_buffer = (uint8_t*)_aligned_malloc(alloc_size, CACHE_LINE_SIZE);
#else
    if (posix_memalign((void**)&t_local_arena->raw_buffer, CACHE_LINE_SIZE, alloc_size) != 0) {
        free(t_local_arena);
        t_local_arena = NULL;
        return;
    }
#endif

    t_local_arena->capacity = alloc_size;
    t_local_arena->offset = 0;
    t_local_arena->free_list = NULL;
    t_local_arena->total_allocations = 0;
    t_local_arena->total_frees = 0;
}

void* memguard_thread_alloc(size_t size) {
    // Auto-initialize if the thread hasn't created its arena yet
    if (!t_local_arena) {
        memguard_init_thread_arena(DEFAULT_SLAB_SIZE);
        if (!t_local_arena) return NULL;
    }

    size_t payload_size = align_to_cache(size);
    size_t total_req_size = sizeof(ChunkHeader) + payload_size;

    // 1. Check free list first (Reusing freed blocks in local cache)
    ChunkHeader *prev = NULL;
    ChunkHeader *curr = t_local_arena->free_list;

    while (curr != NULL) {
        if (curr->is_free && curr->size >= payload_size) {
            curr->is_free = false;
            
            // Remove from free list
            if (prev) {
                prev->next = curr->next;
            } else {
                t_local_arena->free_list = curr->next;
            }

            t_local_arena->total_allocations++;
            // Return pointer immediately after the 64-byte header
            return (void*)((uint8_t*)curr + sizeof(ChunkHeader));
        }
        prev = curr;
        curr = curr->next;
    }

    // 2. Linear Bump Allocation from raw thread buffer
    if (t_local_arena->offset + total_req_size > t_local_arena->capacity) {
        // Out of memory in this thread's local slab!
        return NULL; 
    }

    ChunkHeader *header = (ChunkHeader*)&t_local_arena->raw_buffer[t_local_arena->offset];
    header->size = payload_size;
    header->is_free = false;
    header->next = NULL;

    t_local_arena->offset += total_req_size;
    t_local_arena->total_allocations++;

    return (void*)((uint8_t*)header + sizeof(ChunkHeader));
}

void memguard_thread_free(void* ptr) {
    if (!ptr || !t_local_arena) return;

    // Move back 64 bytes to reach the ChunkHeader
    ChunkHeader *header = (ChunkHeader*)((uint8_t*)ptr - sizeof(ChunkHeader));
    header->is_free = true;

    // Prepend to thread-local free list for instant reuse
    header->next = t_local_arena->free_list;
    t_local_arena->free_list = header;
    t_local_arena->total_frees++;
}

void memguard_destroy_thread_arena(void) {
    if (!t_local_arena) return;

#if defined(_WIN32)
    _aligned_free(t_local_arena->raw_buffer);
#else
    free(t_local_arena->raw_buffer);
#endif

    free(t_local_arena);
    t_local_arena = NULL;
}
