#include "hal/posix_device.hpp"
#include "common/aligned_buffer.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>
#include <cstring>

// 1. Kunal's Safety Gate (Extended)
bool passes_safety_gating(const std::string& target_path, uint64_t total_bytes) {
    std::cout << "[*] Running critical safety checks on " << target_path << "...\n";

    if (target_path.find("/dev/loop") != 0) {
        std::cerr << "[FATAL ERROR] Dev mode active. Target is NOT a /dev/loop device. Aborting.\n";
        return false;
    }

    const uint64_t MAX_TEST_SIZE = 2ULL * 1024 * 1024 * 1024; // 2GB
    if (total_bytes > MAX_TEST_SIZE) {
        std::cerr << "[FATAL ERROR] Device capacity exceeds 2GB test limit. Aborting.\n";
        return false;
    }

    std::ifstream mounts_file("/proc/mounts");
    if (!mounts_file.is_open()) {
        std::cerr << "[FATAL ERROR] Could not read /proc/mounts to verify safety. Aborting.\n";
        return false;
    }

    std::string line;
    while (std::getline(mounts_file, line)) {
        std::istringstream iss(line);
        std::string mounted_device, mount_point;
        
        if (iss >> mounted_device >> mount_point) {
            if (mounted_device == target_path) {
                std::cerr << "[FATAL ERROR] Target " << target_path 
                          << " is actively mounted at " << mount_point << ". Aborting.\n";
                return false;
            }
            if (target_path.find("/dev/sda") != std::string::npos || 
                target_path.find("/dev/nvme0n1") != std::string::npos) {
                std::cerr << "[FATAL ERROR] Attempted access to primary system drive. Aborting.\n";
                return false;
            }
        }
    }

    std::cout << "[+] Safety checks passed. Device is isolated and safe to wipe.\n";
    return true;
}

// 2. Real Hardware Wiper using your HAL
bool wipe_block_device(aegis::hal::IBlockDevice& dev) {
    uint32_t sector_size = dev.sector_size();
    uint64_t total_sectors = dev.total_sectors();
    
    // 1MB chunk size (2048 sectors of 512 bytes)
    uint32_t chunk_sectors = 2048; 
    size_t chunk_bytes = static_cast<size_t>(chunk_sectors) * sector_size;

    // Use AlignedBuffer so O_DIRECT doesn't trigger EINVAL
    aegis::common::AlignedBuffer buffer(chunk_bytes, 4096);
    std::memset(buffer.data(), 0x00, buffer.size());

    std::cout << "[*] Starting NIST SP 800-88 Clear (Single Pass 0x00) via Direct I/O...\n";

    uint64_t current_lba = 0;
    while (current_lba < total_sectors) {
        uint32_t sectors_to_write = static_cast<uint32_t>(std::min<uint64_t>(chunk_sectors, total_sectors - current_lba));
        
        // Write the aligned block directly to physical hardware
        if (!dev.write_sector(current_lba, buffer)) {
            std::cerr << "\n[-] I/O Error writing at LBA " << current_lba << "\n";
            return false;
        }

        current_lba += sectors_to_write;

        double pct = (static_cast<double>(current_lba) / total_sectors) * 100.0;
        std::cout << "{\"progress_pct\": " << pct << ", \"lba\": " << current_lba << "}\n";
    }

    std::cout << "[SUCCESS] Entire drive sanitized with unbuffered O_DIRECT physical writes.\n";
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: sudo ./aegis_cli <target_device>\n";
        return 1;
    }

    if (::geteuid() != 0) {
        std::cerr << "[-] Error: Root privileges required for raw block access.\n";
        return 1;
    }

    std::string target_drive = argv[1];

    // Read device size for pre-check
    int fd = open(target_drive.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[ERROR] Could not open " << target_drive << ".\n";
        return 1;
    }

    uint64_t total_bytes = 0;
    ioctl(fd, BLKGETSIZE64, &total_bytes);
    close(fd);

    if (!passes_safety_gating(target_drive, total_bytes)) {
        return 1; 
    }

    std::cout << "[*] Handing off to POSIX Direct I/O HAL Layer...\n";
    
    aegis::hal::PosixBlockDevice real_device;
    if (!real_device.open(target_drive)) {
        std::cerr << "[-] Failed to open physical device handle.\n";
        return 1;
    }

    wipe_block_device(real_device);
    real_device.close();

    return 0;
}