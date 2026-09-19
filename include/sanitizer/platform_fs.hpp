#ifndef AEGIS_PLATFORM_FS_HPP
#define AEGIS_PLATFORM_FS_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>

// ---------------------------------------------------------------------------
// Platform filesystem layer.
//
// Everything in the sanitizer that has to talk to OS-specific filesystem
// internals lives behind this interface. FileShredder itself stays completely
// OS-agnostic; exactly one of platform_fs_posix.cpp / platform_fs_win32.cpp is
// compiled into the build.
//
//   POSIX   -> FS_IOC_FIEMAP, statfs, ftruncate, fallocate(PUNCH_HOLE), fdatasync
//   Win32   -> FSCTL_GET_RETRIEVAL_POINTERS, GetDiskFreeSpaceW, SetEndOfFile,
//              FSCTL_FILE_LEVEL_TRIM, FlushFileBuffers
// ---------------------------------------------------------------------------

namespace aegis::sanitizer::platform {

// Result of a file-slack elimination attempt.
struct SlackResult {
    bool eliminated = false;
    std::string status = "NOT_ATTEMPTED";  // SUCCESS | SUCCESS_CLUSTER_MODE | SKIPPED_* | FAILED_*
    std::string mode = "UNKNOWN";          // EXTENT | CLUSTER | UNKNOWN
    uint64_t unit_size = 0;                // block size (extent mode) or cluster size (cluster mode)
    uint64_t bytes_overwritten = 0;        // bytes actually written into the tail unit
    std::string fs_name = "UNKNOWN";       // human-readable filesystem name
};

// Result of a discard / TRIM attempt. invoked == true only if the kernel or the
// storage stack actually accepted the discard. Never report a TRIM that the
// filesystem refused.
struct DiscardResult {
    bool invoked = false;
    std::string status = "NOT_ATTEMPTED";  // SUCCESS | FAILED_UNSUPPORTED_FS | FAILED_* | SKIPPED_*
};

// Overwrite the bytes between the file's logical EOF and the end of its last
// allocated block/cluster, using `pattern` (repeated) as fill.
//
// Strategy is chosen per filesystem; see the implementation files. The file's
// logical size is always restored before returning, including on every failure
// path.
SlackResult eliminate_slack_space(const std::filesystem::path& path,
                                  uint64_t logical_size,
                                  const std::vector<uint8_t>& pattern);

// Ask the storage stack to deallocate/TRIM the file's blocks.
DiscardResult discard_file_blocks(const std::filesystem::path& path,
                                  uint64_t logical_size);

// Force any buffered writes for this file out of the OS cache onto the media.
// Call this between the overwrite passes and read-back verification, otherwise
// verification can be satisfied by the page cache instead of the disk.
bool flush_file_to_media(const std::filesystem::path& path);

// Human-readable filesystem name for the volume holding `path`.
std::string detect_filesystem_name(const std::filesystem::path& path);

} // namespace aegis::sanitizer::platform

#endif // AEGIS_PLATFORM_FS_HPP