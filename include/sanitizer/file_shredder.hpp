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

// How the tail-of-file allocation unit was determined for slack elimination.
enum class SlackMode {
    UNKNOWN,
    EXTENT,   // FIEMAP-backed (ext4 / XFS / btrfs ...)
    CLUSTER   // statfs-backed (FAT32 / exFAT / NTFS-3G ...)
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

    // Slack space elimination
    bool slack_space_eliminated = false;
    std::string slack_space_status = "NOT_ATTEMPTED";
    std::string slack_space_mode = "UNKNOWN";      // EXTENT | CLUSTER | UNKNOWN
    uint64_t allocation_unit_bytes = 0;            // block size (extent) or cluster size (FAT)
    uint64_t slack_bytes_overwritten = 0;

    // Discard / TRIM
    bool trim_invoked = false;
    std::string trim_status = "NOT_ATTEMPTED";     // SUCCESS | FAILED_UNSUPPORTED_FS | FAILED_ERRNO_n | ...

    // Verification
    bool verification_passed = false;
    double calculated_entropy = 0.0;
    std::string verification_type = "NONE";

    // Metadata / directory-entry scrub
    bool metadata_scrub_completed = false;

    std::string filesystem_type = "UNKNOWN";       // human-readable fs name where the target lived
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

    // Slack elimination now reports which strategy ran, the allocation unit it used,
    // and how many bytes it actually overwrote.
    bool eliminate_slack_space(const std::filesystem::path& path,
                               uint64_t logical_size,
                               std::string& out_status,
                               SlackMode& out_mode,
                               uint64_t& out_unit_size,
                               uint64_t& out_bytes_overwritten,
                               std::string& out_fs_name);

    bool verify_target_pattern(const std::filesystem::path& path, uint64_t size, uint8_t expected_byte);
    bool verify_entropy(const std::filesystem::path& path, uint64_t size, double& out_entropy);

    // Returns true only if the discard actually succeeded; out_status explains failures.
    bool deallocate_blocks(int fd, uint64_t size, std::string& out_status);

    bool scrub_metadata(const std::filesystem::path& path);
    std::string get_standard_name() const;
    std::vector<uint8_t> get_final_pass_pattern() const;

    static std::string slack_mode_to_string(SlackMode mode);
};

} // namespace aegis::sanitizer

#endif // AEGIS_FILE_SHREDDER_HPP