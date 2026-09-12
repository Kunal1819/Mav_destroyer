#include "sanitizer/file_shredder.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <climits>
#include <unistd.h>

namespace fs = std::filesystem;

void print_banner() {
    std::cout << "=====================================================\n";
    std::cout << "        AEGIS FORENSIC DATA SANITIZATION SUITE       \n";
    std::cout << "=====================================================\n";
}

void print_usage(const char* prog) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " shred <file_path> [--passes N] [--no-zero]\n";
    std::cout << "  " << prog << " wipe-disk <device_path> [--method METHOD] [--force]\n\n";
    std::cout << "Disk Wipe Methods (via nwipe):\n";
    std::cout << "  zero        - Single pass zero overwrite (NIST SP 800-88 Clear)\n";
    std::cout << "  dod522022m  - DoD 5220.22-M 3-pass standard\n";
    std::cout << "  gutmann     - Gutmann 35-pass sanitization\n\n";
    std::cout << "Safety Flags:\n";
    std::cout << "  --force     - Mandatory confirmation when targeting physical media (e.g., USB)\n";
    std::cout << "=====================================================\n";
}

// Inspects /proc/mounts and /proc/swaps to guarantee the target doesn't house the host OS
static bool is_system_or_mounted_storage(const std::string& target_dev, std::string& detected_mount) {
    char resolved_target[PATH_MAX];
    if (!realpath(target_dev.c_str(), resolved_target)) {
        return false;
    }
    std::string canonical_target(resolved_target);

    // 1. Check active filesystem mounts
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string mnt_dev, mnt_point;
        if (iss >> mnt_dev >> mnt_point) {
            char resolved_mnt[PATH_MAX];
            if (realpath(mnt_dev.c_str(), resolved_mnt)) {
                std::string canonical_mnt(resolved_mnt);
                
                // Triggers if target matches directly or if a mounted partition belongs to the drive
                // Example: target is /dev/sda and mounted device is /dev/sda1
                if (canonical_mnt.rfind(canonical_target, 0) == 0) {
                    if (mnt_point == "/" || mnt_point == "/boot" || 
                        mnt_point == "/boot/efi" || mnt_point == "/home" || 
                        mnt_point == "/usr" || mnt_point == "/var") {
                        detected_mount = mnt_point + " (" + canonical_mnt + ")";
                        return true;
                    }
                }
            }
        }
    }

    // 2. Check active Linux swap partitions
    std::ifstream swaps("/proc/swaps");
    while (std::getline(swaps, line)) {
        if (line.empty() || line[0] == 'F') continue; // Skip header
        std::istringstream iss(line);
        std::string swap_dev;
        if (iss >> swap_dev) {
            char resolved_swap[PATH_MAX];
            if (realpath(swap_dev.c_str(), resolved_swap)) {
                std::string canonical_swap(resolved_swap);
                if (canonical_swap.rfind(canonical_target, 0) == 0) {
                    detected_mount = "[ACTIVE SWAP] (" + canonical_swap + ")";
                    return true;
                }
            }
        }
    }

    return false;
}

int handle_shred(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "[-] Error: Missing target file path.\n";
        return 1;
    }

    std::string target_file = argv[2];
    if (!fs::exists(target_file)) {
        std::cerr << "[-] Error: File not found: " << target_file << "\n";
        return 1;
    }

    aegis::sanitizer::FileShredder shredder;
    aegis::sanitizer::ShredConfig cfg;
    cfg.iterations = 3;
    cfg.zero_fill = true;
    cfg.clear_slack = true;
    cfg.remove = true;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--passes" && i + 1 < argc) {
            cfg.iterations = std::stoul(argv[++i]);
        } else if (arg == "--no-zero") {
            cfg.zero_fill = false;
        }
    }

    std::cout << "[*] Dispatching FileShredder engine...\n";
    bool ok = shredder.shred_file(target_file, cfg);
    return ok ? 0 : 1;
}

int handle_wipe_disk(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "[-] Error: Missing device path (e.g., /dev/loop3 or /dev/sdb).\n";
        return 1;
    }

    std::string device = argv[2];
    std::string method = "zero";
    bool force = false;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--method" && i + 1 < argc) {
            method = argv[++i];
        } else if (arg == "--force") {
            force = true;
        }
    }

    // Privilege verification
    if (::getuid() != 0) {
        std::cerr << "[-] Error: Disk wiping requires root privileges (run with sudo).\n";
        return 1;
    }

    // Verify existence of target block device node
    if (!fs::exists(device)) {
        std::cerr << "[-] Error: Block device does not exist: " << device << "\n";
        return 1;
    }

    // System Protection Gate: Prevent host OS destruction
    std::string conflict_mount;
    if (is_system_or_mounted_storage(device, conflict_mount)) {
        std::cerr << "[-] CRITICAL SAFETY BLOCK: Target device " << device 
                  << " contains critical system partition: " << conflict_mount << "!\n";
        std::cerr << "[-] Aegis refused operation to preserve host system integrity.\n";
        return 1;
    }

    // Force Flag Gate: Physical disk safeguard
    bool is_loop = (device.rfind("/dev/loop", 0) == 0);
    if (!is_loop && !force) {
        std::cerr << "[-] PHYSICAL MEDIA DETECTED: Target " << device << " is not a loopback sandbox device!\n";
        std::cerr << "[-] All data and partition tables on this drive will be destroyed.\n";
        std::cerr << "[-] Append '--force' to authorize physical device sanitization:\n";
        std::cerr << "    sudo " << argv[0] << " wipe-disk " << device << " --force [--method " << method << "]\n";
        return 1;
    }

    std::cout << "[*] Initiating Block-Level Sanitization on " << device << "\n";
    std::cout << "  [*] Orchestrating backend: nwipe\n";
    std::cout << "  [*] Selected standard: " << method << "\n";

    std::string cmd = "nwipe --autonuke --nogui --method=" + method + " " + device;
    int ret = std::system(cmd.c_str());

    if (ret == 0) {
        std::cout << "[+] Disk sanitization successfully completed via nwipe.\n";
        return 0;
    }

    std::cerr << "[-] nwipe execution failed with code: " << ret << "\n";
    return 1;
}

int main(int argc, char* argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string subcommand = argv[1];

    if (subcommand == "shred") {
        return handle_shred(argc, argv);
    } else if (subcommand == "wipe-disk") {
        return handle_wipe_disk(argc, argv);
    } else {
        std::cerr << "[-] Unknown subcommand: " << subcommand << "\n";
        print_usage(argv[0]);
        return 1;
    }
}