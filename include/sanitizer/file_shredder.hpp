#ifndef AEGIS_FILE_SHREDDER_HPP
#define AEGIS_FILE_SHREDDER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>

namespace aegis::sanitizer {

enum class SanitizationMethod {
    NIST_800_88_CLEAR, // 1-pass: 0x00
    DOD_5220_22_M,     // 3-pass: Fixed 0x00 -> Fixed 0xFF -> PRNG Random
    PRNG_CUSTOM,       // N-pass PRNG + optional 0x00
    ZERO_ONLY,         // Simple zero fill
    GUTMANN            // 35-pass Gutmann
};

struct ShredConfig {
    SanitizationMethod method = SanitizationMethod::NIST_800_88_CLEAR;
    uint32_t passes = 1;
    bool zero_fill = true;
    size_t buffer_size = 64 * 1024;
    bool recursive = false;
    std::string report_path = "";
};

struct AuditRecord {
    std::string target_path;
    std::string sanitization_standard;
    uint64_t file_size_bytes = 0;
    uint32_t passes_completed = 0;
    bool trim_invoked = false;
    bool verification_passed = false;
    double calculated_entropy = 0.0;
    std::string verification_type = "NONE";
    bool metadata_scrub_completed = false;   // NEW: tracks rename/unlink success
    std::string status = "PENDING";
    std::string start_time;
    std::string end_time;
};

class FileShredder {
public:
    explicit FileShredder(ShredConfig config = ShredConfig());

    bool shred(const std::filesystem::path& target_path);
    bool shred_file(const std::filesystem::path& file_path);
    bool shred_directory(const std::filesystem::path& dir_path);
    bool export_audit_json(const std::filesystem::path& output_json_path);

    const std::vector<AuditRecord>& get_records() const { return records_; }

private:
    ShredConfig config_;
    std::vector<AuditRecord> records_;

    bool execute_passes(const std::filesystem::path& path, uint64_t size, uint32_t& passes_executed);
    bool verify_target_pattern(const std::filesystem::path& path, uint64_t size, uint8_t expected_byte);
    bool verify_entropy(const std::filesystem::path& path, uint64_t size, double& out_entropy);
    void deallocate_blocks(int fd, uint64_t size);
    bool scrub_metadata(const std::filesystem::path& path);   // CHANGED: void -> bool
    std::string get_standard_name() const;
};

} // namespace aegis::sanitizer

#endif // AEGIS_FILE_SHREDDER_HPP