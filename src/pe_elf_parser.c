#include "../include/pe_elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Platform-specific headers for low-level structure definitions
#if defined(_WIN32)
    #include <windows.h>
#else
    #include <elf.h>
#endif

// Helper function to inspect Windows Portable Executable (.sys / .exe) headers
static BinaryAnalysisResult parse_pe_bytes(const uint8_t *buffer, size_t file_size) {
    BinaryAnalysisResult result = {0};
    result.parsing_successful = false;

    // 1. Verify DOS Header Magic Bytes ("MZ")
    if (file_size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z') {
        return result;
    }

    // 2. Locate NT Header Offset (e_lfanew at 0x3C offset)
    int32_t pe_offset = *(int32_t*)(buffer + 0x3C);
    if (pe_offset < 0 || (size_t)pe_offset + 24 > file_size) {
        return result;
    }

    // 3. Verify PE Signature ("PE\0\0")
    const uint8_t *pe_header = buffer + pe_offset;
    if (pe_header[0] != 'P' || pe_header[1] != 'E' || pe_header[2] != 0 || pe_header[3] != 0) {
        return result;
    }

    // 4. Extract Machine Type and Section Count from File Header
    uint16_t machine = *(uint16_t*)(pe_header + 4);
    uint16_t num_sections = *(uint16_t*)(pe_header + 6);
    
    result.architecture = (uint32_t)machine;
    result.section_count = (size_t)num_sections;

    // 5. Extract Entry Point & Optional Header information
    uint16_t optional_header_size = *(uint16_t*)(pe_header + 20);
    if (optional_header_size > 0) {
        // Read AddressOfEntryPoint (offset 16 inside Optional Header)
        uint32_t entry_point_rva = *(uint32_t*)(pe_header + 24 + 16);
        result.entry_point = (uint64_t)entry_point_rva;
    }

    result.parsing_successful = true;
    return result;
}

// Helper function to inspect Linux ELF (.ko / binary) headers
static BinaryAnalysisResult parse_elf_bytes(const uint8_t *buffer, size_t file_size) {
    BinaryAnalysisResult result = {0};
    result.parsing_successful = false;

    // 1. Check Magic Bytes (0x7F 'E' 'L' 'F')
    if (file_size < 64 || buffer[0] != 0x7F || buffer[1] != 'E' || buffer[2] != 'L' || buffer[3] != 'F') {
        return result;
    }

    // 2. Check Bit Width (1 = 32-bit, 2 = 64-bit)
    uint8_t elf_class = buffer[4];

    if (elf_class == 2) { // 64-bit ELF
#if defined(__linux__) || defined(__ELF__)
        const Elf64_Ehdr *elf_hdr = (const Elf64_Ehdr*)buffer;
        result.architecture = elf_hdr->e_machine;
        result.entry_point = elf_hdr->e_entry;
        result.section_count = elf_hdr->e_shnum;
        result.parsing_successful = true;
#else
        // Manual offset parsing if building on non-Linux platform
        result.architecture = *(uint16_t*)(buffer + 18);
        result.entry_point = *(uint64_t*)(buffer + 24);
        result.section_count = *(uint16_t*)(buffer + 60);
        result.parsing_successful = true;
#endif
    }

    return result;
}

// Main Binary Parser Endpoint
BinaryAnalysisResult parse_binary_file(const char *file_path) {
    BinaryAnalysisResult result = {0};
    strncpy(result.file_path, file_path, sizeof(result.file_path) - 1);

    FILE *file = fopen(file_path, "rb");
    if (!file) return result;

    // Determine file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (size <= 0) {
        fclose(file);
        return result;
    }

    // Read file payload into memory
    uint8_t *buffer = (uint8_t*)malloc((size_t)size);
    if (!buffer) {
        fclose(file);
        return result;
    }

    fread(buffer, 1, (size_t)size, file);
    fclose(file);

    // Try PE parser first, then ELF parser
    result = parse_pe_bytes(buffer, (size_t)size);
    if (!result.parsing_successful) {
        result = parse_elf_bytes(buffer, (size_t)size);
    }

    free(buffer);
    return result;
}
