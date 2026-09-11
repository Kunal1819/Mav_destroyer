#pragma once

#include "hal/block_device.hpp"
#include <string>

namespace aegis::hal {

class PosixBlockDevice final : public IBlockDevice {
public:
    PosixBlockDevice();
    ~PosixBlockDevice() override;

    PosixBlockDevice(const PosixBlockDevice&) = delete;
    PosixBlockDevice& operator=(const PosixBlockDevice&) = delete;

    PosixBlockDevice(PosixBlockDevice&& other) noexcept;
    PosixBlockDevice& operator=(PosixBlockDevice&& other) noexcept;

    bool open(const std::string& path) override;
    void close() override;

    bool write_sector(uint64_t lba, const aegis::common::AlignedBuffer& buffer) override;
    bool read_sector(uint64_t lba, aegis::common::AlignedBuffer& buffer) override;

    [[nodiscard]] bool is_open() const noexcept override;
    [[nodiscard]] uint32_t sector_size() const noexcept override;
    [[nodiscard]] uint64_t total_sectors() const noexcept override;

private:
    int fd_{-1};
    std::string path_;
    uint32_t sector_size_{4096};
    uint64_t total_sectors_{0};

    void query_device_geometry();
};

} // namespace aegis::hal