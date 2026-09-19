#include "sanitizer/platform_fs.hpp"

#if defined(__linux__) || defined(__unix__)

#include <iostream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

// ---------------------------------------------------------------------------
// Filesystem magic numbers. linux/magic.h does not carry all of these on every
// distro / kernel header version, so they are defined defensively.
// ---------------------------------------------------------------------------
#ifndef MSDOS_SUPER_MAGIC
#define MSDOS_SUPER_MAGIC 0x00004d44 // FAT12 / FAT16 / FAT32 (vfat driver)
#endif
#ifndef EXFAT_SUPER_MAGIC
#define EXFAT_SUPER_MAGIC 0x2011BAB0 // exfat driver (kernel >= 5.7)
#endif
#ifndef NTFS_SB_MAGIC
#define NTFS_SB_MAGIC 0x5346544e // in-kernel ntfs / ntfs3
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

namespace aegis::sanitizer::platform {

namespace {

// Filesystems that allocate in whole clusters and expose no FIEMAP. For these
// the tail allocation unit comes from statfs() instead of the extent map.
bool is_cluster_allocated_fs(unsigned long fs_type) {
    return fs_type == static_cast<unsigned long>(MSDOS_SUPER_MAGIC) ||
           fs_type == static_cast<unsigned long>(EXFAT_SUPER_MAGIC) ||
           fs_type == static_cast<unsigned long>(NTFS_SB_MAGIC);
}

// Copy-on-write filesystems where "grow the file and write into the tail" is
// not guaranteed to reuse the original physical block. btrfs may relocate the
// extent instead, leaving stale data at the old physical address untouched.
// Mirrors is_cow_filesystem() in platform_fs_win32.cpp (ReFS).
bool is_cow_filesystem(unsigned long fs_type) {
    return fs_type == static_cast<unsigned long>(BTRFS_SUPER_MAGIC);
}

std::string fs_type_name(unsigned long fs_type) {
    switch (fs_type) {
    case static_cast<unsigned long>(MSDOS_SUPER_MAGIC): return "FAT (vfat)";
    case static_cast<unsigned long>(EXFAT_SUPER_MAGIC): return "exFAT";
    case static_cast<unsigned long>(NTFS_SB_MAGIC):     return "NTFS";
    case static_cast<unsigned long>(EXT4_SUPER_MAGIC):  return "ext2/ext3/ext4";
    case static_cast<unsigned long>(XFS_SUPER_MAGIC):   return "XFS";
    case static_cast<unsigned long>(BTRFS_SUPER_MAGIC): return "btrfs";
    case static_cast<unsigned long>(TMPFS_MAGIC):       return "tmpfs";
    case static_cast<unsigned long>(FUSE_SUPER_MAGIC):  return "FUSE";
    default: {
        std::stringstream ss;
        ss << "UNKNOWN(0x" << std::hex << fs_type << ")";
        return ss.str();
    }
    }
}

} // namespace

std::string detect_filesystem_name(const std::filesystem::path& path) {
    struct statfs sfs;
    if (statfs(path.c_str(), &sfs) != 0) return "UNKNOWN";
    return fs_type_name(static_cast<unsigned long>(sfs.f_type));
}

bool flush_file_to_media(const std::filesystem::path& path) {
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) return false;
    const bool ok = (fdatasync(fd) == 0);
    close(fd);
    return ok;
}

// ---------------------------------------------------------------------------
// FILE SLACK SPACE ELIMINATION (POSIX)
//
//   EXTENT mode  (ext4 / XFS / btrfs): FS_IOC_FIEMAP confirms the file owns a
//                real physical extent and is not stored inline in the inode.
//                Allocation unit from fstat().st_blksize.
//
//   CLUSTER mode (FAT32 / exFAT / NTFS): no FIEMAP in these drivers. FAT-family
//                filesystems allocate whole clusters, so the tail cluster is
//                already owned by the file; unit from statfs().f_bsize. There is
//                no inline-data concept.
//
// Both then run: grow logical EOF to the allocation-unit boundary (reusing the
// already-allocated tail unit rather than allocating a new one), overwrite the
// exposed tail bytes, flush, restore the original logical size. The physical
// bytes stay overwritten; only the size metadata is rolled back.
//
// Caveat: on Copy-on-Write filesystems (btrfs, ZFS) the ftruncate grow may
// relocate the tail rather than reuse it. CLUSTER mode cannot verify reuse at
// all since there is no extent map to consult - it relies on the FAT allocation
// model being in-place, which it is.
// ---------------------------------------------------------------------------
SlackResult eliminate_slack_space(const std::filesystem::path& path,
                                  uint64_t logical_size,
                                  const std::vector<uint8_t>& pattern) {
    SlackResult r;

    if (logical_size == 0) {
        r.status = "SKIPPED_EMPTY_FILE";
        r.eliminated = true;
        return r;
    }
    if (pattern.empty()) {
        r.status = "FAILED_EMPTY_PATTERN";
        return r;
    }

    int fd = open(path.c_str(), O_RDWR);
    if (fd < 0) {
        r.status = "FAILED_OPEN_FILE";
        std::cerr << "[-] Slack: failed to open file for R/W: " << path << "\n";
        return r;
    }

    // ---- 1. Identify the filesystem and pick a strategy ---------------------
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        r.status = "FAILED_FSTAT";
        return r;
    }

    struct statfs sfs;
    const bool have_statfs = (fstatfs(fd, &sfs) == 0);
    const unsigned long fs_magic = have_statfs ? static_cast<unsigned long>(sfs.f_type) : 0UL;
    r.fs_name = have_statfs ? fs_type_name(fs_magic) : "UNKNOWN";

    const bool cluster_fs = have_statfs && is_cluster_allocated_fs(fs_magic);

    if (have_statfs && is_cow_filesystem(fs_magic)) {
        close(fd);
        r.mode = "UNKNOWN";
        r.status = "SKIPPED_COW_FILESYSTEM";
        std::cerr << "[!] Slack: " << r.fs_name
                  << " is copy-on-write; grow-and-overwrite is not guaranteed to reach the original block.\n";
        return r;
    }

    uint64_t unit_size = 0;
    if (cluster_fs && have_statfs && sfs.f_bsize > 0) {
        unit_size = static_cast<uint64_t>(sfs.f_bsize);   // cluster size
    } else if (st.st_blksize > 0) {
        unit_size = static_cast<uint64_t>(st.st_blksize); // block size
    } else {
        unit_size = 4096;
    }
    r.unit_size = unit_size;

    const uint64_t remainder = logical_size % unit_size;
    if (remainder == 0) {
        close(fd);
        r.mode = cluster_fs ? "CLUSTER" : "EXTENT";
        r.status = "SKIPPED_NO_SLACK";
        r.eliminated = true;
        return r;
    }

    // ---- 2. EXTENT mode pre-checks (FIEMAP) --------------------------------
    bool used_cluster_fallback = false;
    r.mode = cluster_fs ? "CLUSTER" : "EXTENT";

    if (!cluster_fs) {
        constexpr uint32_t kMaxExtents = 32;
        const size_t fiemap_size = sizeof(struct fiemap) + (kMaxExtents * sizeof(struct fiemap_extent));
        std::vector<uint8_t> fiemap_buffer(fiemap_size, 0);

        struct fiemap* fmap = reinterpret_cast<struct fiemap*>(fiemap_buffer.data());
        fmap->fm_start = 0;
        fmap->fm_length = logical_size;
        fmap->fm_flags = FIEMAP_FLAG_SYNC;
        fmap->fm_extent_count = kMaxExtents;

        if (ioctl(fd, FS_IOC_FIEMAP, fmap) < 0) {
            const int err = errno;
            if (err == ENOTTY || err == EOPNOTSUPP || err == ENOTSUP) {
                // Unknown filesystem with no extent map. Fall back to the
                // allocation-unit approach as best effort and label it clearly
                // rather than silently calling it a normal success.
                used_cluster_fallback = true;
                r.mode = "CLUSTER";
                std::cerr << "[!] Slack: no FIEMAP on " << r.fs_name
                          << " - falling back to allocation-unit (cluster) mode.\n";
            } else {
                close(fd);
                r.status = "FAILED_IOCTL_ERROR";
                std::cerr << "[-] Slack: FS_IOC_FIEMAP ioctl error (errno: " << err << ")\n";
                return r;
            }
        } else {
            if (fmap->fm_mapped_extents == 0) {
                close(fd);
                r.status = "FAILED_NO_EXTENTS";
                std::cerr << "[-] Slack: no physical extents mapped (sparse/inline file).\n";
                return r;
            }

            const struct fiemap_extent& last_extent = fmap->fm_extents[fmap->fm_mapped_extents - 1];

            // ext4 inline-data stores tiny files inside the inode; btrfs inlines
            // files below max_inline (often ~2KB). No tail block to grow into.
            if (last_extent.fe_flags & FIEMAP_EXTENT_DATA_INLINE) {
                close(fd);
                r.status = "SKIPPED_INLINE_INODE_DATA";
                r.eliminated = true;
                return r;
            }
        }
    }

    const uint64_t target_size = logical_size + (unit_size - remainder);
    const size_t bytes_to_overwrite = static_cast<size_t>(target_size - logical_size);

    // ---- 3. Grow logical EOF to the allocation-unit boundary ---------------
    if (ftruncate(fd, static_cast<off_t>(target_size)) != 0) {
        const int err = errno;
        close(fd);
        r.status = "FAILED_FTRUNCATE_GROW";
        std::cerr << "[-] Slack: ftruncate grow failed (errno: " << err << ")\n";
        return r;
    }

    // ---- 4. Seek to the start of slack (original logical EOF) --------------
    if (lseek(fd, static_cast<off_t>(logical_size), SEEK_SET) == static_cast<off_t>(-1)) {
        const int err = errno;
        ftruncate(fd, static_cast<off_t>(logical_size));
        close(fd);
        r.status = "FAILED_SEEK_EOF";
        std::cerr << "[-] Slack: lseek to logical EOF failed (errno: " << err << ")\n";
        return r;
    }

    // ---- 5. Overwrite slack with the final-pass pattern --------------------
    std::vector<uint8_t> write_buf(bytes_to_overwrite);
    for (size_t i = 0; i < bytes_to_overwrite; ++i) {
        write_buf[i] = pattern[i % pattern.size()];
    }

    size_t total_written = 0;
    while (total_written < bytes_to_overwrite) {
        ssize_t written = write(fd, write_buf.data() + total_written, bytes_to_overwrite - total_written);
        if (written <= 0) {
            if (written < 0 && errno == EINTR) continue;
            const int err = errno;
            ftruncate(fd, static_cast<off_t>(logical_size));
            close(fd);
            r.status = "FAILED_WRITE_SLACK";
            std::cerr << "[-] Slack: write to slack bytes failed (errno: " << err << ")\n";
            return r;
        }
        total_written += static_cast<size_t>(written);
    }

    // ---- 6. Flush to physical media before shrinking back ------------------
    if (fdatasync(fd) != 0) {
        const int err = errno;
        ftruncate(fd, static_cast<off_t>(logical_size));
        close(fd);
        r.status = "FAILED_FDATASYNC";
        std::cerr << "[-] Slack: fdatasync failed (errno: " << err << ")\n";
        return r;
    }

    // ---- 7. Restore the original logical size (metadata only) --------------
    if (ftruncate(fd, static_cast<off_t>(logical_size)) != 0) {
        const int err = errno;
        close(fd);
        r.status = "FAILED_FTRUNCATE_RESTORE";
        std::cerr << "[-] Slack: ftruncate restore failed (errno: " << err << ")\n";
        return r;
    }

    fdatasync(fd);
    close(fd);

    r.bytes_overwritten = static_cast<uint64_t>(bytes_to_overwrite);
    r.eliminated = true;
    if (used_cluster_fallback)        r.status = "SUCCESS_CLUSTER_FALLBACK";
    else if (r.mode == "CLUSTER")     r.status = "SUCCESS_CLUSTER_MODE";
    else                              r.status = "SUCCESS";
    return r;
}

// ---------------------------------------------------------------------------
// DISCARD / TRIM (POSIX)
//
// Returns invoked == true ONLY if the hole punch actually succeeded. FAT32 and
// exFAT do not implement FALLOC_FL_PUNCH_HOLE, so this legitimately fails on USB
// media and the audit record must say so rather than claiming a TRIM that never
// happened.
// ---------------------------------------------------------------------------
DiscardResult discard_file_blocks(const std::filesystem::path& path, uint64_t logical_size) {
    DiscardResult d;

    if (logical_size == 0) {
        d.status = "SKIPPED_EMPTY_FILE";
        return d;
    }

#if defined(FALLOC_FL_PUNCH_HOLE)
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        d.status = "FAILED_OPEN_FILE";
        return d;
    }

    fdatasync(fd);

    if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
                  static_cast<off_t>(logical_size)) != 0) {
        const int err = errno;
        close(fd);
        if (err == EOPNOTSUPP || err == ENOTSUP || err == ENOSYS || err == ENOTTY) {
            d.status = "FAILED_UNSUPPORTED_FS";
            std::cerr << "[!] Discard: filesystem does not support PUNCH_HOLE (no TRIM performed).\n";
        } else {
            d.status = "FAILED_ERRNO_" + std::to_string(err);
            std::cerr << "[-] Discard: fallocate PUNCH_HOLE failed (errno: " << err << ")\n";
        }
        return d;
    }

    fsync(fd);
    close(fd);
    d.invoked = true;
    d.status = "SUCCESS";
    return d;
#else
    (void)path;
    d.status = "UNSUPPORTED_BUILD";
    return d;
#endif
}

} // namespace aegis::sanitizer::platform

#endif // __linux__ || __unix__