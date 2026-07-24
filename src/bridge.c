#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "../include/thread_pool.h"
#include "../include/pe_elf_parser.h"
#include "../include/crypto_simd.h"

// 1. Python wrapper for Allocating Cache-Aligned Slots
static PyObject* py_alloc_slot(PyObject* self, PyObject* args) {
    size_t size;
    if (!PyArg_ParseTuple(args, "n", &size)) return NULL;

    void* ptr = memguard_thread_alloc(size);
    if (!ptr) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate cache-aligned slot");
        return NULL;
    }

    return PyLong_FromVoidPtr(ptr);
}

// 2. Python wrapper for Inspecting Binary Drivers
static PyObject* py_inspect_driver(PyObject* self, PyObject* args) {
    const char *path;
    if (!PyArg_ParseTuple(args, "s", &path)) return NULL;

    BinaryAnalysisResult res = parse_binary_file(path);

    return Py_BuildValue("{s:s, s:b, s:K, s:n}",
        "path", res.file_path,
        "valid", res.parsing_successful,
        "entry_point", res.entry_point,
        "sections", res.section_count
    );
}

// 3. Python wrapper for Hardware SIMD Hashing
static PyObject* py_simd_hash_file(PyObject* self, PyObject* args) {
    const char *path;
    if (!PyArg_ParseTuple(args, "s", &path)) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) {
        PyErr_SetString(PyExc_FileNotFoundError, "Target binary file not found");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = (uint8_t*)malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    SIMDHashResult h = simd_fast_hash(buf, sz);
    free(buf);

    return Py_BuildValue("{s:K, s:K, s:n}",
        "hash_low", h.hash_low,
        "hash_high", h.hash_high,
        "bytes_scanned", h.bytes_scanned
    );
}

// Module Registration Table
static PyMethodDef MemGuardMethods[] = {
    {"alloc_slot", py_alloc_slot, METH_VARARGS, "Allocate 64-byte aligned memory slot"},
    {"inspect_driver", py_inspect_driver, METH_VARARGS, "Parse PE/ELF system driver headers"},
    {"simd_hash_file", py_simd_hash_file, METH_VARARGS, "Vectorized hardware hash of binary file"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef memguard_module = {
    PyModuleDef_HEAD_INIT,
    "memguard_c",
    "Low-level memory organizer and system driver auditor",
    -1,
    MemGuardMethods
};

PyMODINIT_FUNC PyInit_memguard_c(void) {
    return PyModule_Create(&memguard_module);
}
