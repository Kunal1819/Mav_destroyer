#include "hal/posix_device.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <iostream>
#include <cerrno>
#include <cstring>

namespace aegis::hal {

PosixBlockDevice::PosixBlockDevice() = default;

PosixBlockDevice::~PosixBlockDevice() {
    close();
}

PosixBlockDevice::PosixBlockDevice(PosixBlockDevice&& other) noexcept
    : fd_(other.fd_), path_(std::move(other.path_)),
      sector_size_(other.sector_size_), total_sectors_(other.total_sectors_) {
    other.fd_ = -1;
}

PosixBlockDevice& PosixBlockDevice::operator=(PosixBlockDevice&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        path_ = std::move(other.path_);
        sector_size_ = other.sector_size_;
        total_sectors_ = other.total_sectors_;
        other.fd_ = -1;
    }
    return *this;
}

bool PosixBlockDevice::open(const std::string& path) {
    close();

    // O_DIRECT: bypass kernel page cache
    // O_SYNC: commit physical writes before returning
    fd_ = ::open(path.c_str(), O_RDWR | O_DIRECT | O_SYNC);
    if (fd_ < 0) {
        std::cerr << "[-] Failed to open device with O_DIRECT: " 
                  << std::strerror(errno) << " (errno: " << errno << ")\n";
        return false;
    }

    path_ = path;
    query_device_geometry();
    return true;
}

void PosixBlockDevice::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

void PosixBlockDevice::query_device_geometry() {
    if (fd_ < 0) return;

    // 1. Fetch logical sector size
    int blk_size = 0;
    if (::ioctl(fd_, BLKSSZGET, &blk_size) == 0 && blk_size > 0) {
        sector_size_ = static_cast<uint32_t>(blk_size);
    } else {
        sector_size_ = 4096; // Standard fallback
    }

    // 2. Fetch total disk capacity in bytes
    uint64_t total_bytes = 0;
    if (::ioctl(fd_, BLKGETSIZE64, &total_bytes) == 0 && sector_size_ > 0) {
        total_sectors_ = total_bytes / sector_size_;
    }
}

bool PosixBlockDevice::write_sector(uint64_t lba, const aegis::common::AlignedBuffer& buffer) {
    if (fd_ < 0) return false;

    if (reinterpret_cast<uintptr_t>(buffer.data()) % buffer.alignment() != 0) {
        std::cerr << "[-] Error: Buffer pointer is not aligned to sector boundaries.\n";
        return false;
    }

    if (buffer.size() % sector_size_ != 0) {
        std::cerr << "[-] Error: Buffer size must be an exact multiple of sector size.\n";
        return false;
    }

    off_t target_offset = static_cast<off_t>(lba * sector_size_);
    ssize_t bytes_written = ::pwrite(fd_, buffer.data(), buffer.size(), target_offset);

    if (bytes_written < 0 || static_cast<size_t>(bytes_written) != buffer.size()) {
        std::cerr << "[-] pwrite failed at LBA " << lba << ": " 
                  << std::strerror(errno) << " (errno: " << errno << ")\n";
        return false;
    }

    return true;
}

bool PosixBlockDevice::read_sector(uint64_t lba, aegis::common::AlignedBuffer& buffer) {
    if (fd_ < 0) return false;

    if (reinterpret_cast<uintptr_t>(buffer.data()) % buffer.alignment() != 0) {
        std::cerr << "[-] Error: Buffer pointer is not aligned to sector boundaries.\n";
        return false;
    }

    off_t target_offset = static_cast<off_t>(lba * sector_size_);
    ssize_t bytes_read = ::pread(fd_, buffer.data(), buffer.size(), target_offset);

    return (bytes_read > 0 && static_cast<size_t>(bytes_read) == buffer.size());
}


bool PosixBlockDevice::is_open() const noexcept { return fd_ >= 0; }
uint32_t PosixBlockDevice::sector_size() const noexcept { return sector_size_; }
uint64_t PosixBlockDevice::total_sectors() const noexcept { return total_sectors_; }

} // namespace aegis::hal