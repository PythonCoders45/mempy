import sys
from setuptools import setup, find_packages, Extension

extra_compile_args = []
extra_link_args = []

if sys.platform == "win32":
    extra_compile_args = ["/O2", "/arch:AVX2"]
else:
    extra_compile_args = ["-O3", "-mavx2", "-pthread", "-fvisibility=hidden"]
    extra_link_args = ["-pthread"]

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
    packages=find_packages(),
    ext_modules=[memguard_extension],
    python_requires=">=3.8",
)
