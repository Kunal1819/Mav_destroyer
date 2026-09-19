#include "sanitizer/file_shredder.hpp"
#include "sanitizer/platform_fs.hpp"

#include <iostream>
#include <fstream>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <array>

namespace aegis::sanitizer
{

    static std::string get_iso_timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

    FileShredder::FileShredder(ShredConfig config) : config_(std::move(config)) {}

    std::string FileShredder::get_standard_name() const
    {
        switch (config_.method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
            return "NIST SP 800-88 Rev. 1 (Clear - 1 Pass Zero)";
        case SanitizationMethod::DOD_5220_22_M:
            return "DoD 5220.22-M (3-Pass: 0x00 -> 0xFF -> PRNG)";
        case SanitizationMethod::PRNG_CUSTOM:
            return "Custom Multi-Pass PRNG Entropy Scrub";
        case SanitizationMethod::ZERO_ONLY:
            return "Single Pass Zero Fill";
        case SanitizationMethod::GUTMANN:
            return "Gutmann Method (35-Pass)";
        }
        return "Unknown Standard";
    }

    // The pattern the slack-space overwrite should use, so the tail of the last
    // block/cluster matches whatever the final content pass wrote.
    std::vector<uint8_t> FileShredder::get_final_pass_pattern() const
    {
        auto random_block = []() -> std::vector<uint8_t>
        {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint16_t> dist(0, 255);
            std::vector<uint8_t> rnd_pattern(512);
            for (auto &b : rnd_pattern)
            {
                b = static_cast<uint8_t>(dist(gen));
            }
            return rnd_pattern;
        };

        switch (config_.method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
        case SanitizationMethod::ZERO_ONLY:
            return {0x00};

        case SanitizationMethod::DOD_5220_22_M:
            // DoD final pass (Pass 3) is PRNG random noise
            return random_block();

        case SanitizationMethod::PRNG_CUSTOM:
            if (config_.zero_fill)
            {
                return {0x00};
            }
            return random_block();

        case SanitizationMethod::GUTMANN:
            // Gutmann final passes (32-35) are pseudo-random noise
            return random_block();
        }
        return {0x00};
    }

    bool FileShredder::verify_target_pattern(const std::filesystem::path &path, uint64_t size, uint8_t expected_byte)
    {
        if (size == 0)
            return true;

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open())
            return false;

        std::vector<char> buffer(config_.buffer_size, 0);
        uint64_t bytes_checked = 0;

        while (bytes_checked < size)
        {
            size_t to_read = std::min(static_cast<uint64_t>(buffer.size()), size - bytes_checked);
            in.read(buffer.data(), to_read);
            std::streamsize bytes_read = in.gcount();
            if (bytes_read <= 0)
                break;

            for (std::streamsize i = 0; i < bytes_read; ++i)
            {
                if (static_cast<uint8_t>(buffer[i]) != expected_byte)
                {
                    return false;
                }
            }
            bytes_checked += bytes_read;
        }

        return bytes_checked == size;
    }

    bool FileShredder::verify_entropy(const std::filesystem::path &path, uint64_t size, double &out_entropy)
    {
        out_entropy = 0.0;
        if (size == 0)
        {
            out_entropy = 0.0;
            return true;
        }

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open())
            return false;

        std::array<uint64_t, 256> frequencies{};
        frequencies.fill(0);

        std::vector<char> buffer(config_.buffer_size, 0);
        uint64_t total_read = 0;

        while (total_read < size)
        {
            size_t to_read = std::min(static_cast<uint64_t>(buffer.size()), size - total_read);
            in.read(buffer.data(), to_read);
            std::streamsize bytes_read = in.gcount();
            if (bytes_read <= 0)
                break;

            for (std::streamsize i = 0; i < bytes_read; ++i)
            {
                frequencies[static_cast<uint8_t>(buffer[i])]++;
            }
            total_read += bytes_read;
        }

        if (total_read == 0)
            return false;

        double entropy = 0.0;
        for (int i = 0; i < 256; ++i)
        {
            if (frequencies[i] > 0)
            {
                double p = static_cast<double>(frequencies[i]) / static_cast<double>(total_read);
                entropy -= p * std::log2(p);
            }
        }

        out_entropy = entropy;
        double threshold = (size < 1024) ? 7.0 : 7.80;
        return (out_entropy >= threshold);
    }

    bool FileShredder::execute_passes(const std::filesystem::path &path, uint64_t size, uint32_t &passes_executed)
    {
        passes_executed = 0;
        if (size == 0)
            return true;

        std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
        if (!stream.is_open())
        {
            std::cerr << "[-] Failed to open file for overwrite: " << path << "\n";
            return false;
        }

        std::vector<char> buffer(config_.buffer_size);
        std::random_device rd;
        std::mt19937_64 prng(rd());
        std::uniform_int_distribution<uint64_t> dist;

        auto write_pass_internal = [&](const auto &fill_chunk) -> bool
        {
            stream.seekp(0, std::ios::beg);
            if (stream.fail())
                return false;

            uint64_t written = 0;
            while (written < size)
            {
                size_t chunk = std::min(static_cast<uint64_t>(buffer.size()), size - written);
                fill_chunk(buffer.data(), chunk);

                stream.write(buffer.data(), chunk);
                if (stream.bad() || stream.fail())
                {
                    std::cerr << "[-] I/O write failure on target: " << path << "\n";
                    return false;
                }
                written += chunk;
            }
            stream.flush();
            if (stream.bad() || stream.fail())
                return false;

            passes_executed++;
            return true;
        };

        auto write_constant_pass = [&](uint8_t byte_val) -> bool
        {
            return write_pass_internal([&](char *buf, size_t chunk)
                                       { std::fill_n(buf, chunk, static_cast<char>(byte_val)); });
        };

        auto write_random_pass = [&]() -> bool
        {
            return write_pass_internal([&](char *buf, size_t chunk)
                                       {
            for (size_t i = 0; i < chunk; i += sizeof(uint64_t)) {
                uint64_t r = dist(prng);
                size_t copy_bytes = std::min(sizeof(uint64_t), chunk - i);
                std::memcpy(buf + i, &r, copy_bytes);
            } });
        };

        auto write_pattern_pass = [&](const std::vector<uint8_t> &pat) -> bool
        {
            return write_pass_internal([&](char *buf, size_t chunk)
                                       {
            for (size_t i = 0; i < chunk; ++i) {
                buf[i] = static_cast<char>(pat[i % pat.size()]);
            } });
        };

        switch (config_.method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
        case SanitizationMethod::ZERO_ONLY:
            if (!write_constant_pass(0x00))
                return false;
            break;

        case SanitizationMethod::DOD_5220_22_M:
            if (!write_constant_pass(0x00))
                return false;
            if (!write_constant_pass(0xFF))
                return false;
            if (!write_random_pass())
                return false;
            break;

        case SanitizationMethod::PRNG_CUSTOM:
            for (uint32_t i = 0; i < config_.passes; ++i)
            {
                if (!write_random_pass())
                    return false;
            }
            if (config_.zero_fill)
            {
                if (!write_constant_pass(0x00))
                    return false;
            }
            break;

        case SanitizationMethod::GUTMANN:
        {
            for (int i = 0; i < 4; ++i)
            {
                if (!write_random_pass())
                    return false;
            }

            std::vector<std::vector<uint8_t>> patterns = {
                {0x55}, {0xAA}, {0x92, 0x49, 0x24}, {0x49, 0x24, 0x92}, {0x24, 0x92, 0x49}, {0x00}, {0x11}, {0x22}, {0x33}, {0x44}, {0x55}, {0x66}, {0x77}, {0x88}, {0x99}, {0xAA}, {0xBB}, {0xCC}, {0xDD}, {0xEE}, {0xFF}, {0x92, 0x49, 0x24}, {0x49, 0x24, 0x92}, {0x24, 0x92, 0x49}, {0x6D, 0xB6, 0xDB}, {0xB6, 0xDB, 0x6D}, {0xDB, 0x6D, 0xB6}};
            std::shuffle(patterns.begin(), patterns.end(), prng);

            for (const auto &pat : patterns)
            {
                if (!write_pattern_pass(pat))
                    return false;
            }

            for (int i = 0; i < 4; ++i)
            {
                if (!write_random_pass())
                    return false;
            }
            break;
        }
        }

        stream.close();
        return true;
    }

    // ---------------------------------------------------------------------------
    // Directory-entry slack cleansing.
    //
    // Renames through an equal-length mask first so the full original name slot in
    // the directory record is overwritten, then shrinks the name to force record
    // consolidation, then unlinks. Rename failures are surfaced, not swallowed.
    //
    // Effectiveness is filesystem-dependent: this is modelled on ext4's
    // ext4_dir_entry_2 layout. NTFS index records ($INDEX_ROOT/$INDEX_ALLOCATION
    // B-trees), exFAT directory entry sets and FAT32 LFN chains lay names out
    // differently, and NTFS additionally records renames in the USN journal. The
    // final unlink always runs regardless.
    // ---------------------------------------------------------------------------
    bool FileShredder::scrub_metadata(const std::filesystem::path &path)
    {
        namespace fs = std::filesystem;
        std::error_code ec;

        fs::path parent = path.parent_path();
        std::string original_name = path.filename().string();
        size_t len = original_name.length();

        fs::path current_path = path;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(100000, 999999);
        std::string nonce = std::to_string(dist(gen));

        bool all_renames_succeeded = true;

        auto try_rename = [&](const fs::path &target)
        {
            fs::rename(current_path, target, ec);
            if (ec)
            {
                std::cerr << "[-] Metadata scrub: rename failed (" << current_path
                          << " -> " << target << "): " << ec.message() << "\n";
                all_renames_succeeded = false;
                return;
            }
            current_path = target;
        };

        // 1. Full-length zero mask
        try_rename(parent / (std::string(len, '0') + "_" + nonce));

        // 2. Full-length complement mask
        try_rename(parent / (std::string(len, 'A') + "_" + nonce));

        // 3. Shrink the name to force directory record consolidation
        try_rename(parent / ("0_" + nonce));

        // 4. Physical unlink - always attempted, even if masking was incomplete
        fs::remove(current_path, ec);
        if (ec)
        {
            std::cerr << "[-] Metadata scrub: final unlink failed for " << current_path
                      << ": " << ec.message() << "\n";
            return false;
        }

        return all_renames_succeeded;
    }

    bool FileShredder::shred_file(const std::filesystem::path &file_path)
    {
        namespace fs = std::filesystem;
        AuditRecord record;
        record.target_path = file_path.string();
        record.sanitization_standard = get_standard_name();
        record.start_time = get_iso_timestamp();

        std::error_code ec;
        if (!fs::is_regular_file(file_path, ec))
        {
            record.status = "SKIPPED_NOT_REGULAR_FILE";
            record.end_time = get_iso_timestamp();
            records_.push_back(record);
            return false;
        }

        uint64_t file_size = fs::file_size(file_path, ec);
        record.file_size_bytes = file_size;
        record.filesystem_type = platform::detect_filesystem_name(file_path);

        // 1. OVERWRITE PASSES
        uint32_t passes_executed = 0;
        if (!execute_passes(file_path, file_size, passes_executed))
        {
            record.status = "FAILED_OVERWRITE";
            record.end_time = get_iso_timestamp();
            records_.push_back(record);
            return false;
        }
        record.passes_completed = passes_executed;

        // 2. FLUSH TO MEDIA
        // Must happen before verification, otherwise the read-back can be served
        // from the OS page cache and "verify" a write that never reached the disk.
        platform::flush_file_to_media(file_path);

        // 3. FILE SLACK SPACE ELIMINATION (extent mode on ext4/XFS, cluster mode
        //    on FAT/exFAT/NTFS). Runs before TRIM so discard cannot disturb it.
        {
            const platform::SlackResult slack =
                platform::eliminate_slack_space(file_path, file_size, get_final_pass_pattern());

            record.slack_space_eliminated = slack.eliminated;
            record.slack_space_status = slack.status;
            record.slack_space_mode = slack.mode;
            record.allocation_unit_bytes = slack.unit_size;
            record.slack_bytes_overwritten = slack.bytes_overwritten;
            if (record.filesystem_type == "UNKNOWN" && slack.fs_name != "UNKNOWN")
            {
                record.filesystem_type = slack.fs_name;
            }
        }

        // 4. VERIFICATION PASS (MUST PRECEDE TRIM TO PREVENT FALSE DISCARD READS)
        bool is_final_pass_zero = (config_.method == SanitizationMethod::NIST_800_88_CLEAR ||
                                   config_.method == SanitizationMethod::ZERO_ONLY ||
                                   (config_.method == SanitizationMethod::PRNG_CUSTOM && config_.zero_fill));

        if (is_final_pass_zero)
        {
            record.verification_type = "BYTE_ZERO_CHECK";
            record.verification_passed = verify_target_pattern(file_path, file_size, 0x00);
            record.calculated_entropy = 0.0;
        }
        else
        {
            record.verification_type = "SHANNON_ENTROPY_CHECK";
            record.verification_passed = verify_entropy(file_path, file_size, record.calculated_entropy);
        }

        // 5. DISCARD / TRIM
        {
            const platform::DiscardResult discard =
                platform::discard_file_blocks(file_path, file_size);
            record.trim_invoked = discard.invoked;
            record.trim_status = discard.status;
        }

        // 6. EQUAL-LENGTH METADATA SCRUB & REMOVAL
        record.metadata_scrub_completed = scrub_metadata(file_path);

        const bool slack_ok = record.slack_space_eliminated ||
                              record.slack_space_status.rfind("SKIPPED", 0) == 0;

        if (!record.verification_passed)
        {
            record.status = "FAILED_VERIFICATION";
        }
        else if (!record.metadata_scrub_completed || !slack_ok)
        {
            record.status = "SUCCESS_WITH_WARNINGS";
        }
        else
        {
            record.status = "SUCCESS_VERIFIED";
        }

        record.end_time = get_iso_timestamp();
        records_.push_back(record);

        // Payload overwrite verified is the bar for a true return; warnings are
        // reported through the record, not by failing the call.
        return record.verification_passed;
    }

    bool FileShredder::shred_directory(const std::filesystem::path &dir_path)
    {
        namespace fs = std::filesystem;
        std::error_code ec;

        if (!fs::is_directory(dir_path, ec))
        {
            return false;
        }

        std::vector<fs::path> files_to_shred;
        std::vector<fs::path> dirs_to_remove;

        for (auto it = fs::recursive_directory_iterator(dir_path, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it)
        {
            if (it->is_regular_file())
            {
                files_to_shred.push_back(it->path());
            }
            else if (it->is_directory())
            {
                dirs_to_remove.push_back(it->path());
            }
        }

        for (const auto &file : files_to_shred)
        {
            shred_file(file);
        }

        for (auto it = dirs_to_remove.rbegin(); it != dirs_to_remove.rend(); ++it)
        {
            fs::remove(*it, ec);
        }

        fs::remove(dir_path, ec);
        return true;
    }

    bool FileShredder::shred(const std::filesystem::path &target_path)
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        if (fs::is_directory(target_path, ec))
        {
            if (!config_.recursive)
            {
                std::cerr << "[-] Target is a directory. Use -r / --recursive to shred directories.\n";
                return false;
            }
            return shred_directory(target_path);
        }
        return shred_file(target_path);
    }

    bool FileShredder::export_audit_json(const std::filesystem::path &output_json_path)
    {
        std::ofstream out(output_json_path);
        if (!out.is_open())
            return false;

        out << "{\n";
        out << "  \"audit_meta\": {\n";
        out << "    \"tool\": \"Aegis Forensic Data Sanitization Suite\",\n";
        out << "    \"standard\": \"" << get_standard_name() << "\",\n";
        out << "    \"generated_at\": \"" << get_iso_timestamp() << "\"\n";
        out << "  },\n";
        out << "  \"records\": [\n";

        for (size_t i = 0; i < records_.size(); ++i)
        {
            const auto &r = records_[i];
            out << "    {\n";
            out << "      \"target_path\": \"" << r.target_path << "\",\n";
            out << "      \"filesystem_type\": \"" << r.filesystem_type << "\",\n";
            out << "      \"sanitization_standard\": \"" << r.sanitization_standard << "\",\n";
            out << "      \"file_size_bytes\": " << r.file_size_bytes << ",\n";
            out << "      \"passes_completed\": " << r.passes_completed << ",\n";
            out << "      \"slack_space_eliminated\": " << (r.slack_space_eliminated ? "true" : "false") << ",\n";
            out << "      \"slack_space_status\": \"" << r.slack_space_status << "\",\n";
            out << "      \"slack_space_mode\": \"" << r.slack_space_mode << "\",\n";
            out << "      \"allocation_unit_bytes\": " << r.allocation_unit_bytes << ",\n";
            out << "      \"slack_bytes_overwritten\": " << r.slack_bytes_overwritten << ",\n";
            out << "      \"trim_invoked\": " << (r.trim_invoked ? "true" : "false") << ",\n";
            out << "      \"trim_status\": \"" << r.trim_status << "\",\n";
            out << "      \"verification_type\": \"" << r.verification_type << "\",\n";
            out << "      \"calculated_entropy\": " << std::fixed << std::setprecision(4) << r.calculated_entropy << ",\n";
            out << "      \"verification_passed\": " << (r.verification_passed ? "true" : "false") << ",\n";
            out << "      \"metadata_scrub_completed\": " << (r.metadata_scrub_completed ? "true" : "false") << ",\n";
            out << "      \"status\": \"" << r.status << "\",\n";
            out << "      \"start_time\": \"" << r.start_time << "\",\n";
            out << "      \"end_time\": \"" << r.end_time << "\"\n";
            out << "    }" << (i + 1 < records_.size() ? "," : "") << "\n";
        }

        out << "  ]\n";
        out << "}\n";
        return true;
    }

} // namespace aegis::sanitizer