#pragma once

#include "common/aligned_buffer.hpp"
#include <string>
#include <cstdint>

namespace aegis::hal {

class IBlockDevice {
public:
    virtual ~IBlockDevice() = default;

    virtual bool open(const std::string& path) = 0;
    virtual void close() = 0;

    virtual bool write_sector(uint64_t lba, const aegis::common::AlignedBuffer& buffer) = 0;
    virtual bool read_sector(uint64_t lba, aegis::common::AlignedBuffer& buffer) = 0;

    [[nodiscard]] virtual bool is_open() const noexcept = 0;
    [[nodiscard]] virtual uint32_t sector_size() const noexcept = 0;
    [[nodiscard]] virtual uint64_t total_sectors() const noexcept = 0;
};

} // namespace aegis::hal