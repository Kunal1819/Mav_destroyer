#pragma once

#include <cstdint>
#include <cstddef>

namespace aegis::common {

// Standard LBA (Logical Block Address) scalar
using Lba = uint64_t;

// Sector size constants
inline constexpr uint32_t STANDARD_SECTOR_SIZE = 512;
inline constexpr uint32_t ADVANCED_SECTOR_SIZE = 4096; // 4K native

// Default chunk size for bulk unbuffered streaming writes (1MB)
inline constexpr size_t DEFAULT_IO_CHUNK_SIZE = 1024 * 1024;

} // namespace aegis::common