#ifndef PE_ELF_PARSER_H
#define PE_ELF_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char file_path[256];
    uint32_t architecture;   // e.g., x86_64, ARM64
    uint64_t entry_point;     // Memory address where code starts executing
    size_t section_count;    // Total number of sections (.text, .data, etc.)
    bool is_executable;      // Flag indicating executable permissions
    bool is_signed;          // Indicates presence of a security directory/signature
    bool parsing_successful;
} BinaryAnalysisResult;

// Public API
BinaryAnalysisResult parse_binary_file(const char *file_path);

#endif // PE_ELF_PARSER_H
