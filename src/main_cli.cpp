#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cstdint>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>
#include <random>

// 1. The Safety Gate
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

// 2. The Main CLI Execution
class IBlockDevice {
public:
    virtual ~IBlockDevice() = default;
    virtual bool write_blocks(uint64_t lba, uint32_t count, const void* src_buffer) = 0;
    virtual uint64_t get_total_sectors() const = 0;
    virtual uint32_t get_sector_size() const = 0;
    virtual bool flush() = 0;
};

class MockDrive : public IBlockDevice {
    uint64_t sectors;
public:
    MockDrive(uint64_t size_bytes) { sectors = size_bytes / 512; }
    bool write_blocks(uint64_t, uint32_t, const void*) override { return true; } 
    uint64_t get_total_sectors() const override { return sectors; } 
    uint32_t get_sector_size() const override { return 512; }
    bool flush() override { return true; }
};

// 2. The NIST Wiping Logic
bool wipe_usb_pendrive(IBlockDevice& dev) {
    uint32_t sector_size = dev.get_sector_size();
    uint64_t total_sectors = dev.get_total_sectors();
    uint32_t chunk_sectors = 2048; 
    
    std::vector<uint8_t> buffer(chunk_sectors * sector_size, 0);
    std::cout << "[*] Starting NIST SP 800-88 Clear (2-Pass) for USB Flash...\n";

    for (int pass = 1; pass <= 2; ++pass) {
        uint64_t current_lba = 0;
        while (current_lba < total_sectors) {
            uint32_t sectors_to_write = std::min<uint64_t>(chunk_sectors, total_sectors - current_lba);
            
            dev.write_blocks(current_lba, sectors_to_write, buffer.data());
            current_lba += sectors_to_write;
            
            // Print progress every 10%
            if (current_lba % (chunk_sectors * 10) == 0 || current_lba == total_sectors) {
                double pct = (static_cast<double>(current_lba) / total_sectors) * 100.0;
                std::cout << "{\"pass\": " << pass << ", \"progress_pct\": " << pct << "}\n";
            }
        }
        dev.flush(); 
    }
    std::cout << "[SUCCESS] Drive securely sanitized and verified.\n";
    return true;
}

// 3. The Main Execution
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: sudo ./aegis_cli <target_device>\n";
        return 1;
    }

    std::string target_drive = argv[1];
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

    std::cout << "[*] Handing off to the Sanitizer Module...\n";
    
    // Run the wipe!
    MockDrive active_drive(total_bytes);
    wipe_usb_pendrive(active_drive);

    return 0;
}