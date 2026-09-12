#include "sanitizer/file_shredder.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdlib>
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
    std::cout << "  " << prog << " wipe-disk <device_path> [--method METHOD]\n\n";
    std::cout << "Disk Wipe Methods (via nwipe):\n";
    std::cout << "  zero        - Single pass zero overwrite (NIST SP 800-88 Clear)\n";
    std::cout << "  dod522022m  - DoD 5220.22-M 3-pass standard\n";
    std::cout << "  gutmann     - Gutmann 35-pass sanitization\n";
    std::cout << "=====================================================\n";
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
        std::cerr << "[-] Error: Missing device path (e.g., /dev/loop3).\n";
        return 1;
    }

    std::string device = argv[2];
    std::string method = "zero";

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--method" && i + 1 < argc) {
            method = argv[++i];
        }
    }

    // Safety Gate: Enforce loopback during development/sandbox phase
    if (device.find("/dev/loop") != 0) {
        std::cerr << "[-] SAFETY LOCK: Only /dev/loop devices are permitted in test builds!\n";
        std::cerr << "    Requested target: " << device << "\n";
        return 1;
    }

    if (::getuid() != 0) {
        std::cerr << "[-] Error: Disk wiping requires root privileges (run with sudo).\n";
        return 1;
    }

    std::cout << "[*] Initiating Block-Level Sanitization on " << device << "\n";
    std::cout << "  [*] Orchestrating backend: nwipe\n";
    std::cout << "  [*] Selected standard: " << method << "\n";

    std::string cmd = "nwipe --nogui --autonuke --method=" + method + " " + device;
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