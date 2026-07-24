import os
import ctypes
from typing import Dict, Any, Optional

# Import the compiled C extension
try:
    import memguard_c
except ImportError as e:
    raise ImportError(
        "Could not load the low-level C extension 'memguard_c'. "
        "Please build the C extension first using 'python setup.py build_ext --inplace'."
    ) from e


class MemorySlot:
    """Represents a 64-byte CPU cache-aligned memory block allocated in C."""

    def __init__(self, size_bytes: int):
        if size_bytes <= 0:
            raise ValueError("Allocation size must be greater than 0 bytes.")

        self.size = size_bytes
        self.address: int = memguard_c.alloc_slot(size_bytes)

        if not self.address:
            raise MemoryError("Failed to allocate cache-aligned memory slot in C.")

    def get_pointer(self) -> ctypes.c_void_p:
        """Returns a ctypes void pointer to pass to low-level Python C-types interfaces."""
        return ctypes.c_void_p(self.address)

    def __repr__(self) -> str:
        return f"<MemorySlot size={self.size} bytes at {hex(self.address)}>"


def allocate_cache_slot(size_bytes: int) -> MemorySlot:
    """Allocates a 64-byte aligned memory slot for zero-lock thread performance.

    :param size_bytes: Size of requested memory in bytes.
    :return: MemorySlot object wrapping the raw pointer.
    """
    return MemorySlot(size_bytes)


def inspect_binary_driver(file_path: str) -> Dict[str, Any]:
    """Parses executable/driver binary headers (PE or ELF) in raw C speed.

    :param file_path: Path to target file (.sys, .exe, .ko, or binary).
    :return: Dictionary containing entry points, section counts, and architecture info.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Binary file not found: {file_path}")

    return memguard_c.inspect_driver(os.path.abspath(file_path))


def compute_simd_hash(file_path: str) -> Dict[str, Any]:
    """Computes a hardware-accelerated AVX2 vector hash of a file or binary.

    :param file_path: Path to target file.
    :return: Dictionary containing combined hash results and total bytes scanned.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found for SIMD hash: {file_path}")

    raw_hash = memguard_c.simd_hash_file(os.path.abspath(file_path))

    # Combine low and high 64-bit integers into a full 128-bit hex string representation
    combined_hash_128 = (raw_hash["hash_high"] << 64) | raw_hash["hash_low"]
    raw_hash["hash_hex"] = f"{combined_hash_128:032x}"

    return raw_hash
