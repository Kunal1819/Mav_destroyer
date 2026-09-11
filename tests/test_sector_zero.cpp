#include "hal/posix_device.hpp"
#include "common/aligned_buffer.hpp"

#include <iostream>
#include <cstring>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <device_path>\n";
        std::cerr << "Example: sudo " << argv[0] << " /dev/loop3\n";
        return 1;
    }

    std::string dev_path = argv[1];

    // Safety Gate: Refuse to execute on anything except /dev/loop during testing
    if (dev_path.rfind("/dev/loop", 0) != 0) {
        std::cerr << "[-] SAFETY ABORT: Path is not a loop device (" << dev_path << ")!\n";
        return 1;
    }

    if (::geteuid() != 0) {
        std::cerr << "[-] Access Denied: Must run with root privileges (sudo).\n";
        return 1;
    }

    std::cout << "[*] Initializing POSIX Direct I/O on target: " << dev_path << "...\n";

    aegis::hal::PosixBlockDevice device;
    if (!device.open(dev_path)) {
        std::cerr << "[-] Failed to open device: " << dev_path << "\n";
        return 1;
    }

    uint32_t sector_size = device.sector_size();
    std::cout << "[+] Device successfully opened.\n";
    std::cout << "    - Sector Size:  " << sector_size << " bytes\n";
    std::cout << "    - Total Blocks: " << device.total_sectors() << " sectors\n";

    // Allocate a 4096-byte aligned buffer initialized to 0x00
    aegis::common::AlignedBuffer write_buffer(sector_size, 4096);
    std::memset(write_buffer.data(), 0x00, write_buffer.size());

    std::cout << "[*] Executing unbuffered direct write to Sector 0...\n";
    if (!device.write_sector(0, write_buffer)) {
        std::cerr << "[-] Write failed!\n";
        return 1;
    }
    std::cout << "[+] Sector 0 overwritten with 0x00 successfully.\n";

    // Read-back verification pass
    std::cout << "[*] Performing read-back verification of Sector 0...\n";
    aegis::common::AlignedBuffer read_buffer(sector_size, 4096);
    if (!device.read_sector(0, read_buffer)) {
        std::cerr << "[-] Verification read failed!\n";
        return 1;
    }

    bool all_zeros = true;
    for (size_t i = 0; i < read_buffer.size(); ++i) {
        if (read_buffer.data()[i] != 0x00) {
            all_zeros = false;
            break;
        }
    }

    if (all_zeros) {
        std::cout << "[SUCCESS] Read-back confirmed: Sector 0 is completely zeroed out!\n";
    } else {
        std::cerr << "[-] Verification mismatch: Non-zero bytes found in Sector 0.\n";
        return 1;
    }

    device.close();
    return 0;
}