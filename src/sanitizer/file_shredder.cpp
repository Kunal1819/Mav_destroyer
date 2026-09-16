#include "sanitizer/file_shredder.hpp"
#include <iostream>
#include <fstream>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <cmath>
#include <array>

#if defined(__linux__) || defined(__unix__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#endif

// ---------------------------------------------------------------------------
// Filesystem magic numbers.
// linux/magic.h does not carry all of these on every distro / kernel header
// version, so they are defined defensively here.
// ---------------------------------------------------------------------------
#if defined(__linux__)
#ifndef MSDOS_SUPER_MAGIC
#define MSDOS_SUPER_MAGIC 0x00004d44 // FAT12 / FAT16 / FAT32 (vfat driver)
#endif
#ifndef EXFAT_SUPER_MAGIC
#define EXFAT_SUPER_MAGIC 0x2011BAB0 // exfat driver (kernel >= 5.7)
#endif
#ifndef NTFS_SB_MAGIC
#define NTFS_SB_MAGIC 0x5346544e // "NTFS" - in-kernel ntfs / ntfs3
#endif
#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0x0000EF53
#endif
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif
#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif
#endif

namespace aegis::sanitizer
{

#if defined(__linux__)
    namespace
    {
        // Filesystems that allocate storage in whole clusters and expose no FIEMAP.
        // For these the tail allocation unit is read from statfs() instead.
        bool is_cluster_allocated_fs(unsigned long fs_type)
        {
            return fs_type == static_cast<unsigned long>(MSDOS_SUPER_MAGIC) ||
                   fs_type == static_cast<unsigned long>(EXFAT_SUPER_MAGIC) ||
                   fs_type == static_cast<unsigned long>(NTFS_SB_MAGIC);
        }

        std::string fs_type_name(unsigned long fs_type)
        {
            switch (fs_type)
            {
            case static_cast<unsigned long>(MSDOS_SUPER_MAGIC):
                return "FAT (vfat)";
            case static_cast<unsigned long>(EXFAT_SUPER_MAGIC):
                return "exFAT";
            case static_cast<unsigned long>(NTFS_SB_MAGIC):
                return "NTFS";
            case static_cast<unsigned long>(EXT4_SUPER_MAGIC):
                return "ext2/ext3/ext4";
            case static_cast<unsigned long>(XFS_SUPER_MAGIC):
                return "XFS";
            case static_cast<unsigned long>(BTRFS_SUPER_MAGIC):
                return "btrfs";
            case static_cast<unsigned long>(TMPFS_MAGIC):
                return "tmpfs";
            case static_cast<unsigned long>(FUSE_SUPER_MAGIC):
                return "FUSE";
            default:
            {
                std::stringstream ss;
                ss << "UNKNOWN(0x" << std::hex << fs_type << ")";
                return ss.str();
            }
            }
        }
    } // namespace
#endif

    static std::string get_iso_timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

    FileShredder::FileShredder(ShredConfig config) : config_(std::move(config)) {}

    std::string FileShredder::slack_mode_to_string(SlackMode mode)
    {
        switch (mode)
        {
        case SlackMode::EXTENT:
            return "EXTENT";
        case SlackMode::CLUSTER:
            return "CLUSTER";
        case SlackMode::UNKNOWN:
        default:
            return "UNKNOWN";
        }
    }

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

    // ---------------------------------------------------------------------------
    // Discard / TRIM.
    // Returns true ONLY if the hole punch actually succeeded. FAT32/exFAT do not
    // implement FALLOC_FL_PUNCH_HOLE, so this legitimately fails on USB media and
    // the audit record must say so rather than claiming a TRIM that never happened.
    // ---------------------------------------------------------------------------
    bool FileShredder::deallocate_blocks(int fd, uint64_t size, std::string &out_status)
    {
#if defined(__linux__) && defined(FALLOC_FL_PUNCH_HOLE)
        if (fd < 0)
        {
            out_status = "FAILED_BAD_FD";
            return false;
        }
        if (size == 0)
        {
            out_status = "SKIPPED_EMPTY_FILE";
            return false;
        }

        if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, static_cast<off_t>(size)) != 0)
        {
            const int err = errno;
            if (err == EOPNOTSUPP || err == ENOTSUP || err == ENOSYS || err == ENOTTY)
            {
                out_status = "FAILED_UNSUPPORTED_FS";
                std::cerr << "[!] Discard: filesystem does not support PUNCH_HOLE (no TRIM performed).\n";
            }
            else
            {
                out_status = "FAILED_ERRNO_" + std::to_string(err);
                std::cerr << "[-] Discard: fallocate PUNCH_HOLE failed (errno: " << err << ")\n";
            }
            return false;
        }

        fsync(fd);
        out_status = "SUCCESS";
        return true;
#else
        (void)fd;
        (void)size;
        out_status = "UNSUPPORTED_PLATFORM";
        return false;
#endif
    }

    // ---------------------------------------------------------------------------
    // FILE SLACK SPACE ELIMINATION
    //
    // Two strategies behind one entry point:
    //
    //   EXTENT mode  (ext4 / XFS / btrfs): FS_IOC_FIEMAP confirms the file owns a
    //                real physical extent and is not stored inline in the inode.
    //                Allocation unit taken from fstat().st_blksize.
    //
    //   CLUSTER mode (FAT32 / exFAT / NTFS): no FIEMAP exists in these drivers.
    //                FAT-family filesystems allocate in whole clusters, so the tail
    //                cluster is already owned by the file and the allocation unit is
    //                read from statfs().f_bsize. There is no inline-data concept.
    //
    // Both then run the same sequence: grow the logical EOF to the allocation-unit
    // boundary (which reuses the already-allocated tail unit rather than allocating
    // a new one), overwrite the exposed tail bytes, flush, then restore the original
    // logical size. The physical bytes stay overwritten; only the size metadata is
    // rolled back.
    //
    // Caveat (documented, not fixed): on Copy-on-Write filesystems (btrfs, ZFS) the
    // ftruncate grow may relocate the tail rather than reuse it. CLUSTER mode cannot
    // verify reuse at all, since there is no extent map to consult - it relies on the
    // FAT allocation model being in-place, which it is.
    // ---------------------------------------------------------------------------
    bool FileShredder::eliminate_slack_space(const std::filesystem::path &path,
                                             uint64_t logical_size,
                                             std::string &out_status,
                                             SlackMode &out_mode,
                                             uint64_t &out_unit_size,
                                             uint64_t &out_bytes_overwritten,
                                             std::string &out_fs_name)
    {
        out_mode = SlackMode::UNKNOWN;
        out_unit_size = 0;
        out_bytes_overwritten = 0;
        out_fs_name = "UNKNOWN";

#if defined(__linux__)
        if (logical_size == 0)
        {
            out_status = "SKIPPED_EMPTY_FILE";
            return true;
        }

        int fd = open(path.c_str(), O_RDWR);
        if (fd < 0)
        {
            out_status = "FAILED_OPEN_FILE";
            std::cerr << "[-] Slack: failed to open file for R/W: " << path << "\n";
            return false;
        }

        // ---- 1. Identify the filesystem and pick a strategy ------------------
        struct stat st;
        if (fstat(fd, &st) != 0)
        {
            close(fd);
            out_status = "FAILED_FSTAT";
            return false;
        }

        struct statfs sfs;
        bool have_statfs = (fstatfs(fd, &sfs) == 0);
        unsigned long fs_magic = have_statfs ? static_cast<unsigned long>(sfs.f_type) : 0UL;
        out_fs_name = have_statfs ? fs_type_name(fs_magic) : "UNKNOWN";

        const bool cluster_fs = have_statfs && is_cluster_allocated_fs(fs_magic);

        // Allocation unit: cluster size on FAT-family, block size elsewhere.
        uint64_t unit_size = 0;
        if (cluster_fs && have_statfs && sfs.f_bsize > 0)
        {
            unit_size = static_cast<uint64_t>(sfs.f_bsize);
        }
        else if (st.st_blksize > 0)
        {
            unit_size = static_cast<uint64_t>(st.st_blksize);
        }
        else
        {
            unit_size = 4096;
        }
        out_unit_size = unit_size;

        const uint64_t remainder = logical_size % unit_size;
        if (remainder == 0)
        {
            close(fd);
            out_mode = cluster_fs ? SlackMode::CLUSTER : SlackMode::EXTENT;
            out_status = "SKIPPED_NO_SLACK";
            return true;
        }

        // ---- 2. EXTENT mode pre-checks (FIEMAP) ------------------------------
        bool used_cluster_fallback = false;
        SlackMode mode = cluster_fs ? SlackMode::CLUSTER : SlackMode::EXTENT;

        if (!cluster_fs)
        {
            constexpr uint32_t kMaxExtents = 32;
            const size_t fiemap_size = sizeof(struct fiemap) + (kMaxExtents * sizeof(struct fiemap_extent));
            std::vector<uint8_t> fiemap_buffer(fiemap_size, 0);

            struct fiemap *fmap = reinterpret_cast<struct fiemap *>(fiemap_buffer.data());
            fmap->fm_start = 0;
            fmap->fm_length = logical_size;
            fmap->fm_flags = FIEMAP_FLAG_SYNC;
            fmap->fm_extent_count = kMaxExtents;

            if (ioctl(fd, FS_IOC_FIEMAP, fmap) < 0)
            {
                const int err = errno;
                if (err == ENOTTY || err == EOPNOTSUPP || err == ENOTSUP)
                {
                    // Unknown filesystem with no extent map. Fall back to the
                    // allocation-unit approach as best effort and label it clearly
                    // in the audit rather than silently calling it a normal success.
                    used_cluster_fallback = true;
                    mode = SlackMode::CLUSTER;
                    std::cerr << "[!] Slack: no FIEMAP on " << out_fs_name
                              << " - falling back to allocation-unit (cluster) mode.\n";
                }
                else
                {
                    close(fd);
                    out_status = "FAILED_IOCTL_ERROR";
                    std::cerr << "[-] Slack: FS_IOC_FIEMAP ioctl error (errno: " << err << ")\n";
                    return false;
                }
            }
            else
            {
                if (fmap->fm_mapped_extents == 0)
                {
                    close(fd);
                    out_mode = SlackMode::EXTENT;
                    out_status = "FAILED_NO_EXTENTS";
                    std::cerr << "[-] Slack: no physical extents mapped (sparse/inline file).\n";
                    return false;
                }

                const struct fiemap_extent &last_extent = fmap->fm_extents[fmap->fm_mapped_extents - 1];

                // ext4 inline-data feature stores tiny files inside the inode itself;
                // btrfs inlines files below max_inline (often ~2KB). There is no tail
                // block to grow into in that case.
                if (last_extent.fe_flags & FIEMAP_EXTENT_DATA_INLINE)
                {
                    close(fd);
                    out_mode = SlackMode::EXTENT;
                    out_status = "SKIPPED_INLINE_INODE_DATA";
                    return true;
                }
            }
        }

        out_mode = mode;

        const uint64_t target_size = logical_size + (unit_size - remainder);
        const size_t bytes_to_overwrite = static_cast<size_t>(target_size - logical_size);

        // ---- 3. Grow logical EOF to the allocation-unit boundary -------------
        if (ftruncate(fd, static_cast<off_t>(target_size)) != 0)
        {
            const int err = errno;
            close(fd);
            out_status = "FAILED_FTRUNCATE_GROW";
            std::cerr << "[-] Slack: ftruncate grow failed (errno: " << err << ")\n";
            return false;
        }

        // ---- 4. Seek to the start of slack (original logical EOF) ------------
        if (lseek(fd, static_cast<off_t>(logical_size), SEEK_SET) == static_cast<off_t>(-1))
        {
            const int err = errno;
            ftruncate(fd, static_cast<off_t>(logical_size));
            close(fd);
            out_status = "FAILED_SEEK_EOF";
            std::cerr << "[-] Slack: lseek to logical EOF failed (errno: " << err << ")\n";
            return false;
        }

        // ---- 5. Overwrite slack with the same pattern as the final pass ------
        const std::vector<uint8_t> pattern = get_final_pass_pattern();
        std::vector<uint8_t> write_buf(bytes_to_overwrite);
        for (size_t i = 0; i < bytes_to_overwrite; ++i)
        {
            write_buf[i] = pattern[i % pattern.size()];
        }

        size_t total_written = 0;
        while (total_written < bytes_to_overwrite)
        {
            ssize_t written = write(fd, write_buf.data() + total_written, bytes_to_overwrite - total_written);
            if (written <= 0)
            {
                if (written < 0 && errno == EINTR)
                {
                    continue;
                }
                const int err = errno;
                ftruncate(fd, static_cast<off_t>(logical_size));
                close(fd);
                out_status = "FAILED_WRITE_SLACK";
                std::cerr << "[-] Slack: write to slack bytes failed (errno: " << err << ")\n";
                return false;
            }
            total_written += static_cast<size_t>(written);
        }

        // ---- 6. Flush to physical media before shrinking back ----------------
        if (fdatasync(fd) != 0)
        {
            const int err = errno;
            ftruncate(fd, static_cast<off_t>(logical_size));
            close(fd);
            out_status = "FAILED_FDATASYNC";
            std::cerr << "[-] Slack: fdatasync failed (errno: " << err << ")\n";
            return false;
        }

        // ---- 7. Restore the original logical size (metadata only) ------------
        if (ftruncate(fd, static_cast<off_t>(logical_size)) != 0)
        {
            const int err = errno;
            close(fd);
            out_status = "FAILED_FTRUNCATE_RESTORE";
            std::cerr << "[-] Slack: ftruncate restore failed (errno: " << err << ")\n";
            return false;
        }

        fdatasync(fd);
        close(fd);

        out_bytes_overwritten = static_cast<uint64_t>(bytes_to_overwrite);

        if (used_cluster_fallback)
        {
            out_status = "SUCCESS_CLUSTER_FALLBACK";
        }
        else if (mode == SlackMode::CLUSTER)
        {
            out_status = "SUCCESS_CLUSTER_MODE";
        }
        else
        {
            out_status = "SUCCESS";
        }
        return true;
#else
        (void)path;
        (void)logical_size;
        out_status = "UNSUPPORTED_PLATFORM";
        return false;
#endif
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
    // Renames through an equal-length mask first so the full original name_len slot
    // in the directory record is overwritten, then shrinks the name to force record
    // consolidation, then unlinks. Rename failures are surfaced, not swallowed.
    //
    // Note: FAT/exFAT directory entries and NTFS index records do not lay out names
    // the way ext4's ext4_dir_entry_2 does, so the effectiveness of the equal-length
    // mask varies by filesystem. The unlink itself always runs.
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

        // 2. FILE SLACK SPACE ELIMINATION (extent mode or cluster mode)
        SlackMode slack_mode = SlackMode::UNKNOWN;
        record.slack_space_eliminated = eliminate_slack_space(file_path,
                                                             file_size,
                                                             record.slack_space_status,
                                                             slack_mode,
                                                             record.allocation_unit_bytes,
                                                             record.slack_bytes_overwritten,
                                                             record.filesystem_type);
        record.slack_space_mode = slack_mode_to_string(slack_mode);

        // 3. VERIFICATION PASS (MUST PRECEDE TRIM TO PREVENT FALSE DISCARD READS)
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

        // 4. HARDWARE CACHE SYNC & DISCARD / TRIM
#if defined(__linux__) || defined(__unix__)
        int fd = open(file_path.c_str(), O_WRONLY);
        if (fd >= 0)
        {
            fdatasync(fd);
            record.trim_invoked = deallocate_blocks(fd, file_size, record.trim_status);
            close(fd);
        }
        else
        {
            record.trim_status = "FAILED_OPEN_FILE";
        }
#endif

        // 5. EQUAL-LENGTH METADATA SCRUB & REMOVAL
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