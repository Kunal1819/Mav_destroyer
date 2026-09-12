#include "sanitizer/file_shredder.hpp"
#include <iostream>
#include <filesystem>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_real_file>\n";
        return 1;
    }

    std::string target_file = argv[1];

    if (!std::filesystem::exists(target_file)) {
        std::cerr << "[-] Error: File not found: " << target_file << "\n";
        return 1;
    }

    aegis::sanitizer::FileShredder shredder;
    aegis::sanitizer::ShredConfig cfg;
    cfg.iterations = 3;     // 3 PRNG chaos passes
    cfg.zero_fill = true;   // 1 zero pass[cite: 2]
    cfg.clear_slack = true; // Round to filesystem block boundary[cite: 2]
    cfg.remove = true;      // Obfuscate directory record and unlink[cite: 2]

    bool status = shredder.shred_file(target_file, cfg);

    if (status && !std::filesystem::exists(target_file)) {
        std::cout << "\n[SUCCESS] Targeted file permanently destroyed and unlinked.\n";
        return 0;
    }

    std::cerr << "[-] Shredding failed or file still present.\n";
    return 1;
}