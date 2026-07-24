import os
import sys
import platform
from setuptools import setup, Extension

# Define compiler flags based on OS and architecture
extra_compile_args = []
extra_link_args = []

if sys.platform == "win32":
    # MSVC compiler flags for speed optimization and AVX2 vector support
    extra_compile_args = ["/O2", "/arch:AVX2"]
else:
    # GCC/Clang compiler flags for Linux/macOS
    extra_compile_args = [
        "-O3",                  # Maximize performance optimization
        "-mavx2",                # Enable AVX2 hardware SIMD vector intrinsics
        "-pthread",              # Enable thread-local storage support
        "-fvisibility=hidden"   # Keep internal C symbols hidden
    ]
    extra_link_args = ["-pthread"]

# Define the C Extension Module
memguard_extension = Extension(
    name="memguard_c",
    sources=[
        "src/thread_pool.c",
        "src/pe_elf_parser.c",
        "src/crypto_simd.c",
        "src/bridge.c",
    ],
    include_dirs=["include"],
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args,
)

setup(
    name="MemGuard",
    version="0.1.0",
    description="C-accelerated CPU cache memory allocator, SIMD hasher, and driver auditor",
    author="Your Name",
    ext_modules=[memguard_extension],
    python_requires=">=3.8",
)
