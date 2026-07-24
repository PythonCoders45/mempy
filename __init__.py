"""
MemGuard: High-Speed C-Accelerated CPU Memory Organizer and Driver Auditor.
"""

from .core import (
    MemorySlot,
    allocate_cache_slot,
    inspect_binary_driver,
    compute_simd_hash,
)

__version__ = "0.1.0"
__all__ = [
    "MemorySlot",
    "allocate_cache_slot",
    "inspect_binary_driver",
    "compute_simd_hash",
]
