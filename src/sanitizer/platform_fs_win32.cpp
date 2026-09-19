#include "sanitizer/platform_fs.hpp"

#if defined(_WIN32)

// FSCTL_FILE_LEVEL_TRIM requires Windows 8 / Server 2012 headers.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

// ---------------------------------------------------------------------------
// FILE_LEVEL_TRIM compatibility shim.
//
// The MSVC / Windows 8 SDK winioctl.h declares FSCTL_FILE_LEVEL_TRIM *and* the
// FILE_LEVEL_TRIM structures. MinGW-w64 declares the control code but not the
// structures, so "#if defined(FSCTL_FILE_LEVEL_TRIM)" is not a safe test.
// Aegis-prefixed POD equivalents are declared here instead; they match the
// documented ABI and work identically under both toolchains.
// ---------------------------------------------------------------------------
#ifndef FSCTL_FILE_LEVEL_TRIM
#define FSCTL_FILE_LEVEL_TRIM \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 130, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif

typedef struct _AEGIS_FILE_LEVEL_TRIM_RANGE {
    DWORDLONG Offset;
    DWORDLONG Length;
} AEGIS_FILE_LEVEL_TRIM_RANGE;

typedef struct _AEGIS_FILE_LEVEL_TRIM {
    DWORD Key;
    DWORD NumRanges;
    AEGIS_FILE_LEVEL_TRIM_RANGE Ranges[1];
} AEGIS_FILE_LEVEL_TRIM;

typedef struct _AEGIS_FILE_LEVEL_TRIM_OUTPUT {
    DWORD NumRangesProcessed;
} AEGIS_FILE_LEVEL_TRIM_OUTPUT;

#include <iostream>
#include <sstream>
#include <algorithm>

namespace aegis::sanitizer::platform {

namespace {

// -- small helpers ---------------------------------------------------------

std::string narrow(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) {
        out.push_back(static_cast<char>(c < 128 ? c : '?'));
    }
    return out;
}

std::string win_err_status(const char* prefix, DWORD err) {
    std::stringstream ss;
    ss << prefix << err;
    return ss.str();
}

// Volume root ("C:\", "E:\", or a \\?\Volume{...}\ path) for a given file.
std::wstring volume_root_of(const std::filesystem::path& path) {
    wchar_t buf[MAX_PATH + 1] = {0};
    if (!GetVolumePathNameW(path.c_str(), buf, MAX_PATH)) {
        return std::wstring();
    }
    return std::wstring(buf);
}

// Filesystem name as reported by the volume ("NTFS", "exFAT", "FAT32", "ReFS").
std::string fs_name_of(const std::filesystem::path& path) {
    const std::wstring root = volume_root_of(path);
    if (root.empty()) return "UNKNOWN";

    wchar_t fsname[MAX_PATH + 1] = {0};
    if (!GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr,
                               fsname, MAX_PATH)) {
        return "UNKNOWN";
    }
    return narrow(std::wstring(fsname));
}

// Cluster size = sectors-per-cluster * bytes-per-sector. This is the true
// allocation unit on NTFS / exFAT / FAT32, and the thing slack is measured
// against - not the sector size.
uint64_t cluster_size_of(const std::filesystem::path& path) {
    const std::wstring root = volume_root_of(path);
    if (root.empty()) return 0;

    DWORD sectors_per_cluster = 0, bytes_per_sector = 0;
    DWORD free_clusters = 0, total_clusters = 0;
    if (!GetDiskFreeSpaceW(root.c_str(), &sectors_per_cluster, &bytes_per_sector,
                           &free_clusters, &total_clusters)) {
        return 0;
    }
    return static_cast<uint64_t>(sectors_per_cluster) * static_cast<uint64_t>(bytes_per_sector);
}

// Copy-on-write / log-structured filesystems where "grow the file and write into
// the tail" does not overwrite the original physical bytes.
bool is_cow_filesystem(const std::string& fs) {
    return fs == "ReFS";
}

// RAII handle.
class Handle {
public:
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return h_; }
    bool valid() const { return h_ != INVALID_HANDLE_VALUE; }
private:
    HANDLE h_;
};

HANDLE open_rw(const std::filesystem::path& path) {
    return CreateFileW(path.c_str(),
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ,              // keep others from writing under us
                       nullptr,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       nullptr);
}

bool set_size(HANDLE h, uint64_t size) {
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(size);
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
    return SetEndOfFile(h) != 0;
}

bool seek_to(HANDLE h, uint64_t offset) {
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    return SetFilePointerEx(h, li, nullptr, FILE_BEGIN) != 0;
}

// FSCTL_GET_RETRIEVAL_POINTERS is the Win32 analogue of FIEMAP. Its main job
// here is detecting NTFS *resident* files - files small enough (typically under
// ~700-900 bytes) that their data lives inside the MFT record itself rather than
// in any cluster. Those have no tail cluster to grow into, exactly like ext4
// inline data.
enum class ResidencyCheck {
    HAS_EXTENTS,
    RESIDENT_OR_UNSUPPORTED,
    ERROR_OTHER
};

ResidencyCheck check_residency(HANDLE h, DWORD& out_err) {
    STARTING_VCN_INPUT_BUFFER in;
    in.StartingVcn.QuadPart = 0;

    // One RETRIEVAL_POINTERS_BUFFER plus room for a handful of extents.
    struct {
        RETRIEVAL_POINTERS_BUFFER base;
        LARGE_INTEGER spare[64];
    } out_buf;
    ZeroMemory(&out_buf, sizeof(out_buf));

    DWORD bytes_returned = 0;
    const BOOL ok = DeviceIoControl(h, FSCTL_GET_RETRIEVAL_POINTERS,
                                    &in, sizeof(in),
                                    &out_buf, sizeof(out_buf),
                                    &bytes_returned, nullptr);
    if (ok) {
        return (out_buf.base.ExtentCount > 0) ? ResidencyCheck::HAS_EXTENTS
                                              : ResidencyCheck::RESIDENT_OR_UNSUPPORTED;
    }

    out_err = GetLastError();
    switch (out_err) {
    case ERROR_MORE_DATA:
        // Buffer too small, but the file demonstrably has extents.
        return ResidencyCheck::HAS_EXTENTS;
    case ERROR_INVALID_FUNCTION:
        // Resident file, or a filesystem that does not implement this FSCTL
        // (FAT32 / exFAT). Caller decides which by looking at the fs name.
        return ResidencyCheck::RESIDENT_OR_UNSUPPORTED;
    case ERROR_HANDLE_EOF:
        return ResidencyCheck::RESIDENT_OR_UNSUPPORTED;
    default:
        return ResidencyCheck::ERROR_OTHER;
    }
}

} // namespace

// ---------------------------------------------------------------------------

std::string detect_filesystem_name(const std::filesystem::path& path) {
    return fs_name_of(path);
}

bool flush_file_to_media(const std::filesystem::path& path) {
    Handle h(open_rw(path));
    if (!h.valid()) return false;
    return FlushFileBuffers(h.get()) != 0;
}

// ---------------------------------------------------------------------------
// FILE SLACK SPACE ELIMINATION (Win32)
//
// Windows has no FIEMAP, and NTFS / exFAT / FAT32 are all cluster-allocated, so
// there is only one strategy here: CLUSTER mode. The allocation unit comes from
// GetDiskFreeSpaceW (sectors-per-cluster x bytes-per-sector).
//
// Sequence, mirroring the POSIX path:
//   1. Reject cases where grow-and-overwrite provably does not reach the
//      original bytes: compressed, sparse, encrypted, ReFS (CoW).
//   2. FSCTL_GET_RETRIEVAL_POINTERS to catch NTFS resident files (data lives in
//      the MFT record, no tail cluster exists).
//   3. SetEndOfFile to grow the logical size up to the cluster boundary.
//   4. WriteFile the pattern into the exposed tail.
//   5. FlushFileBuffers.
//   6. SetEndOfFile back to the original size - metadata only, the bytes stay.
//
// NTFS note: extending a file does NOT physically write anything; NTFS tracks a
// separate "valid data length" and reads past it return zeros without touching
// the disk. That is exactly why step 4 issues a real WriteFile instead of
// relying on the grow to zero the tail. The write advances VDL and lands on the
// media.
// ---------------------------------------------------------------------------
SlackResult eliminate_slack_space(const std::filesystem::path& path,
                                  uint64_t logical_size,
                                  const std::vector<uint8_t>& pattern) {
    SlackResult r;
    r.mode = "CLUSTER";
    r.fs_name = fs_name_of(path);

    if (logical_size == 0) {
        r.status = "SKIPPED_EMPTY_FILE";
        r.eliminated = true;
        return r;
    }
    if (pattern.empty()) {
        r.status = "FAILED_EMPTY_PATTERN";
        return r;
    }

    // ---- 1. Attributes that break the in-place assumption ------------------
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        r.status = win_err_status("FAILED_GETATTR_", GetLastError());
        return r;
    }
    if (attrs & FILE_ATTRIBUTE_COMPRESSED) {
        // NTFS compression rewrites compression units elsewhere; the tail we
        // would write is not the tail that held the original bytes.
        r.status = "SKIPPED_COMPRESSED_FILE";
        return r;
    }
    if (attrs & FILE_ATTRIBUTE_SPARSE_FILE) {
        r.status = "SKIPPED_SPARSE_FILE";
        return r;
    }
    if (attrs & FILE_ATTRIBUTE_ENCRYPTED) {
        // EFS re-encrypts on write; plaintext remnants are not addressable here.
        r.status = "SKIPPED_ENCRYPTED_FILE";
        return r;
    }
    if (is_cow_filesystem(r.fs_name)) {
        r.status = "SKIPPED_COW_FILESYSTEM";
        std::cerr << "[!] Slack: " << r.fs_name
                  << " is copy-on-write; grow-and-overwrite would not reach the original clusters.\n";
        return r;
    }

    // ---- 2. Allocation unit ------------------------------------------------
    const uint64_t unit_size = cluster_size_of(path);
    if (unit_size == 0) {
        r.status = "FAILED_CLUSTER_SIZE_UNKNOWN";
        return r;
    }
    r.unit_size = unit_size;

    const uint64_t remainder = logical_size % unit_size;
    if (remainder == 0) {
        r.status = "SKIPPED_NO_SLACK";
        r.eliminated = true;
        return r;
    }

    Handle h(open_rw(path));
    if (!h.valid()) {
        r.status = win_err_status("FAILED_OPEN_", GetLastError());
        std::cerr << "[-] Slack: CreateFileW failed for " << path.string() << "\n";
        return r;
    }

    // ---- 3. Resident-file detection (NTFS) ---------------------------------
    DWORD rp_err = 0;
    const ResidencyCheck residency = check_residency(h.get(), rp_err);
    if (residency == ResidencyCheck::ERROR_OTHER) {
        r.status = win_err_status("FAILED_RETRIEVAL_POINTERS_", rp_err);
        return r;
    }
    if (residency == ResidencyCheck::RESIDENT_OR_UNSUPPORTED) {
        if (r.fs_name == "NTFS") {
            // Small file stored inside the MFT record - no tail cluster exists.
            r.status = "SKIPPED_RESIDENT_MFT_DATA";
            r.eliminated = true;
            return r;
        }
        // FAT32 / exFAT simply do not implement this FSCTL. The cluster model
        // still holds, so continue.
    }

    const uint64_t target_size = logical_size + (unit_size - remainder);
    const size_t bytes_to_overwrite = static_cast<size_t>(target_size - logical_size);

    // ---- 4. Grow logical EOF to the cluster boundary -----------------------
    if (!set_size(h.get(), target_size)) {
        r.status = win_err_status("FAILED_SETEOF_GROW_", GetLastError());
        return r;
    }

    // From here on, every failure path must restore the original size.
    auto restore_size = [&]() {
        set_size(h.get(), logical_size);
        FlushFileBuffers(h.get());
    };

    // ---- 5. Seek to the start of slack and write the pattern ---------------
    if (!seek_to(h.get(), logical_size)) {
        const DWORD err = GetLastError();
        restore_size();
        r.status = win_err_status("FAILED_SEEK_EOF_", err);
        return r;
    }

    std::vector<uint8_t> write_buf(bytes_to_overwrite);
    for (size_t i = 0; i < bytes_to_overwrite; ++i) {
        write_buf[i] = pattern[i % pattern.size()];
    }

    size_t total_written = 0;
    while (total_written < bytes_to_overwrite) {
        const DWORD to_write = static_cast<DWORD>(
            std::min<size_t>(bytes_to_overwrite - total_written, 1u << 20));
        DWORD written = 0;
        if (!WriteFile(h.get(), write_buf.data() + total_written, to_write, &written, nullptr) ||
            written == 0) {
            const DWORD err = GetLastError();
            restore_size();
            r.status = win_err_status("FAILED_WRITE_SLACK_", err);
            std::cerr << "[-] Slack: WriteFile into slack failed (GetLastError: " << err << ")\n";
            return r;
        }
        total_written += written;
    }

    // ---- 6. Flush before shrinking back ------------------------------------
    if (!FlushFileBuffers(h.get())) {
        const DWORD err = GetLastError();
        restore_size();
        r.status = win_err_status("FAILED_FLUSH_", err);
        return r;
    }

    // ---- 7. Restore the original logical size (metadata only) --------------
    if (!set_size(h.get(), logical_size)) {
        r.status = win_err_status("FAILED_SETEOF_RESTORE_", GetLastError());
        return r;
    }
    FlushFileBuffers(h.get());

    r.bytes_overwritten = static_cast<uint64_t>(bytes_to_overwrite);
    r.eliminated = true;
    r.status = "SUCCESS_CLUSTER_MODE";
    return r;
}

// ---------------------------------------------------------------------------
// DISCARD / TRIM (Win32)
//
// FSCTL_FILE_LEVEL_TRIM is the Windows equivalent of fallocate(PUNCH_HOLE) for
// this purpose: it tells the storage stack the file's byte ranges no longer hold
// live data, so an SSD can release the underlying NAND. It is NTFS-only and
// needs Windows 8 / Server 2012 or newer - on exFAT / FAT32 it fails, and the
// audit record says so rather than claiming a TRIM that never happened.
// ---------------------------------------------------------------------------
DiscardResult discard_file_blocks(const std::filesystem::path& path, uint64_t logical_size) {
    DiscardResult d;

    if (logical_size == 0) {
        d.status = "SKIPPED_EMPTY_FILE";
        return d;
    }

    Handle h(open_rw(path));
    if (!h.valid()) {
        d.status = win_err_status("FAILED_OPEN_", GetLastError());
        return d;
    }

    FlushFileBuffers(h.get());

    AEGIS_FILE_LEVEL_TRIM trim;
    ZeroMemory(&trim, sizeof(trim));
    trim.Key = 0;
    trim.NumRanges = 1;
    trim.Ranges[0].Offset = 0;
    trim.Ranges[0].Length = logical_size;

    AEGIS_FILE_LEVEL_TRIM_OUTPUT trim_out;
    ZeroMemory(&trim_out, sizeof(trim_out));

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(h.get(), FSCTL_FILE_LEVEL_TRIM,
                         &trim, sizeof(trim),
                         &trim_out, sizeof(trim_out),
                         &bytes_returned, nullptr)) {
        const DWORD err = GetLastError();
        if (err == ERROR_INVALID_FUNCTION || err == ERROR_NOT_SUPPORTED) {
            d.status = "FAILED_UNSUPPORTED_FS";
            std::cerr << "[!] Discard: volume does not support FILE_LEVEL_TRIM (no TRIM performed).\n";
        } else {
            d.status = win_err_status("FAILED_ERR_", err);
            std::cerr << "[-] Discard: FSCTL_FILE_LEVEL_TRIM failed (GetLastError: " << err << ")\n";
        }
        return d;
    }

    if (trim_out.NumRangesProcessed == 0) {
        // The FSCTL succeeded but the storage stack discarded nothing - do not
        // report this as a TRIM.
        d.status = "FAILED_NO_RANGES_PROCESSED";
        return d;
    }

    d.invoked = true;
    d.status = "SUCCESS";
    return d;
}

} // namespace aegis::sanitizer::platform

#endif // _WIN32