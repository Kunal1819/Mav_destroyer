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

void print_banner()
{
    std::cout << "=====================================================\n";
    std::cout << "        AEGIS FORENSIC DATA SANITIZATION SUITE       \n";
    std::cout << "=====================================================\n";
}

void print_usage(const char *prog)
{
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " shred <path> [-r] [--method METHOD] [--passes N] [--no-zero] [--audit <file.json>]\n";
    std::cout << "  " << prog << " wipe-disk <device_path> [--method METHOD] [--force]\n\n";
    std::cout << "Sanitization Methods (--method):\n";
    std::cout << "  nist        - NIST SP 800-88 Clear (Single Pass 0x00) [Default]\n";
    std::cout << "  dod522022m  - DoD 5220.22-M 3-Pass (0x00 -> 0xFF -> PRNG Random)\n";
    std::cout << "  prng        - Custom Multi-Pass Random Noise + Zero Fill\n";
    std::cout << "  zero        - Single Pass Zero Overwrite\n";
    std::cout << "  gutmann     - Gutmann Method (35-Pass)\n\n";
    std::cout << "Options:\n";
    std::cout << "  -r, --recursive        Recursively shred directories and child contents\n";
    std::cout << "  --passes N             Number of PRNG passes (only used with --method prng)\n";
    std::cout << "  --no-zero              Omit final zero-fill pass in PRNG mode\n";
    std::cout << "  --audit <path.json>    Export forensic audit certificate (default: aegis_audit.json)\n";
    std::cout << "  --force                Mandatory confirmation for physical drive wiping\n";
    std::cout << "=====================================================\n";
}

static bool is_system_or_mounted_storage(const std::string &target_dev, std::string &detected_mount)
{
    char resolved_target[PATH_MAX];
    if (!realpath(target_dev.c_str(), resolved_target))
    {
        return false;
    }
    std::string canonical_target(resolved_target);

    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line))
    {
        std::istringstream iss(line);
        std::string mnt_dev, mnt_point;
        if (iss >> mnt_dev >> mnt_point)
        {
            char resolved_mnt[PATH_MAX];
            if (realpath(mnt_dev.c_str(), resolved_mnt))
            {
                std::string canonical_mnt(resolved_mnt);
                if (canonical_mnt.rfind(canonical_target, 0) == 0)
                {
                    if (mnt_point == "/" || mnt_point == "/boot" ||
                        mnt_point == "/boot/efi" || mnt_point == "/home" ||
                        mnt_point == "/usr" || mnt_point == "/var")
                    {
                        detected_mount = mnt_point + " (" + canonical_mnt + ")";
                        return true;
                    }
                }
            }
        }
    }

    std::ifstream swaps("/proc/swaps");
    while (std::getline(swaps, line))
    {
        if (line.empty() || line[0] == 'F')
            continue;
        std::istringstream iss(line);
        std::string swap_dev;
        if (iss >> swap_dev)
        {
            char resolved_swap[PATH_MAX];
            if (realpath(swap_dev.c_str(), resolved_swap))
            {
                std::string canonical_swap(resolved_swap);
                if (canonical_swap.rfind(canonical_target, 0) == 0)
                {
                    detected_mount = "[ACTIVE SWAP] (" + canonical_swap + ")";
                    return true;
                }
            }
        }
    }

    return false;
}

int handle_shred(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "[-] Error: Missing target path to shred.\n";
        return 1;
    }

    std::string target_path = argv[2];
    if (!fs::exists(target_path))
    {
        std::cerr << "[-] Error: Target path not found: " << target_path << "\n";
        return 1;
    }

    aegis::sanitizer::ShredConfig cfg;
    cfg.method = aegis::sanitizer::SanitizationMethod::NIST_800_88_CLEAR;
    std::string method_str = "nist";
    std::string audit_out = "aegis_audit.json";

    for (int i = 3; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-r" || arg == "--recursive")
        {
            cfg.recursive = true;
        }
        else if (arg == "--method" && i + 1 < argc)
        {
            method_str = argv[++i];
            if (method_str == "nist")
            {
                cfg.method = aegis::sanitizer::SanitizationMethod::NIST_800_88_CLEAR;
            }
            else if (method_str == "dod522022m")
            {
                cfg.method = aegis::sanitizer::SanitizationMethod::DOD_5220_22_M;
            }
            else if (method_str == "prng")
            {
                cfg.method = aegis::sanitizer::SanitizationMethod::PRNG_CUSTOM;
            }
            else if (method_str == "zero")
            {
                cfg.method = aegis::sanitizer::SanitizationMethod::ZERO_ONLY;
            }
            else if (method_str == "gutmann")
            {
                cfg.method = aegis::sanitizer::SanitizationMethod::GUTMANN;
            }
            else
            {
                std::cerr << "[-] Unknown method: " << method_str << ". Defaulting to NIST SP 800-88.\n";
            }
        }
        else if (arg == "--passes" && i + 1 < argc)
        {
            cfg.passes = std::stoul(argv[++i]);
        }
        else if (arg == "--no-zero")
        {
            cfg.zero_fill = false;
        }
        else if (arg == "--audit" && i + 1 < argc)
        {
            audit_out = argv[++i];
        }
    }

    if (fs::is_directory(target_path) && !cfg.recursive)
    {
        std::cerr << "[-] Error: Target is a directory. Specify '-r' or '--recursive' to shred folders.\n";
        return 1;
    }

    std::cout << "[*] Dispatching Aegis Sanitizer Engine...\n";
    std::cout << "  [*] Target: " << target_path << "\n";
    std::cout << "  [*] Mode: " << (fs::is_directory(target_path) ? "Recursive Folder Scrub" : "Single File Shred") << "\n";
    std::cout << "  [*] Method: " << method_str << "\n";

    aegis::sanitizer::FileShredder shredder(cfg);
    bool ok = shredder.shred(target_path);

    if (shredder.export_audit_json(audit_out))
    {
        std::cout << "[+] Tamper-evident Audit Certificate saved: " << audit_out << "\n";
    }

    if (ok)
    {
        std::cout << "[+] Operation complete: Sanitization and verification successful.\n";
        return 0;
    }
    else
    {
        std::cerr << "[-] Sanitization encountered errors.\n";
        return 1;
    }
}

int handle_wipe_disk(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "[-] Error: Missing device path (e.g., /dev/loop3 or /dev/sdb).\n";
        return 1;
    }

    std::string device = argv[2];
    std::string method = "zero";
    bool force = false;

    for (int i = 3; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--method" && i + 1 < argc)
        {
            method = argv[++i];
        }
        else if (arg == "--force")
        {
            force = true;
        }
    }

    if (::getuid() != 0)
    {
        std::cerr << "[-] Error: Disk wiping requires root privileges (run with sudo).\n";
        return 1;
    }

    if (!fs::exists(device))
    {
        std::cerr << "[-] Error: Block device does not exist: " << device << "\n";
        return 1;
    }

    std::string conflict_mount;
    if (is_system_or_mounted_storage(device, conflict_mount))
    {
        std::cerr << "[-] CRITICAL SAFETY BLOCK: Target device " << device
                  << " contains critical system partition: " << conflict_mount << "!\n";
        std::cerr << "[-] Aegis refused operation to preserve host system integrity.\n";
        return 1;
    }

    bool is_loop = (device.rfind("/dev/loop", 0) == 0);
    if (!is_loop && !force)
    {
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

    if (ret == 0)
    {
        std::cout << "[+] Disk sanitization successfully completed via nwipe.\n";
        return 0;
    }

    std::cerr << "[-] nwipe execution failed with code: " << ret << "\n";
    return 1;
}

int main(int argc, char *argv[])
{
    print_banner();

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    std::string subcommand = argv[1];

    if (subcommand == "shred")
    {
        return handle_shred(argc, argv);
    }
    else if (subcommand == "wipe-disk")
    {
        return handle_wipe_disk(argc, argv);
    }
    else
    {
        std::cerr << "[-] Unknown subcommand: " << subcommand << "\n";
        print_usage(argv[0]);
        return 1;
    }
}