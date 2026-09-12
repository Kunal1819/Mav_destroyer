#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace aegis::sanitizer {

enum class WipeStandard {
    NIST_CLEAR,     // 1 Zero-fill pass
    DOD_3PASS,      // Pass 1: Random, Pass 2: Complement/Pattern, Pass 3: Random + Zero
    GUTMANN_BASIC   // Custom N-pass sequence
};

struct ShredConfig {
    uint32_t iterations = 3;   // Default 3 passes (like shred.c)[cite: 2]
    bool zero_fill = true;     // Final 0x00 pass to hide shredding[cite: 2]
    bool remove = true;        // Obfuscate directory slot and unlink[cite: 2]
    bool clear_slack = true;   // Round up to filesystem block size[cite: 2]
};

class FileShredder {
public:
    FileShredder() = default;
    ~FileShredder() = default;

    // Primary entry point for surgical file destruction
    bool shred_file(const std::string& filepath, const ShredConfig& config = ShredConfig{});

private:
    // Core engine loops adapted from shred.c[cite: 2]
    bool do_wipefd(int fd, uint64_t target_size, const ShredConfig& config);
    bool dopass(int fd, uint64_t size, int pass_num, int total_passes, bool is_zero_pass);
    bool dosync(int fd);
    
    // Directory slot obfuscation and metadata scrubbing[cite: 2]
    bool wipename(const std::string& filepath);
    bool sync_directory(const std::string& dirpath);
};

} // namespace aegis::sanitizer