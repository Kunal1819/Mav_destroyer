#include "sanitizer/file_shredder.hpp"

#include <iostream>
#include <random>
#include <vector>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

namespace aegis::sanitizer {

namespace {
// Safe universal character set for directory renaming from shred.c
const char NAMESET[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.";
constexpr size_t BUFFER_CHUNK_SIZE = 64 * 1024; // 64KB unbuffered page chunk
}

bool FileShredder::dosync(int fd) {
    if (::fdatasync(fd) == 0) return true;
    if (::fsync(fd) == 0) return true;
    ::sync();
    return true;
}

bool FileShredder::sync_directory(const std::string& dirpath) {
    int dfd = ::open(dirpath.c_str(), O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return false;
    dosync(dfd);
    ::close(dfd);
    return true;
}

bool FileShredder::dopass(int fd, uint64_t size, int pass_num, int total_passes, bool is_zero_pass) {
    std::cout << "  [*] Pass " << pass_num << "/" << total_passes 
              << (is_zero_pass ? " [Zero Fill 0x00]" : " [PRNG Chaos Pattern]") << "...\n";

    std::vector<uint8_t> buffer(BUFFER_CHUNK_SIZE);
    std::random_device rd;
    std::mt19937_64 prng(rd());
    std::uniform_int_distribution<uint64_t> dist;

    // Reset file head offset to 0
    if (::lseek(fd, 0, SEEK_SET) != 0) {
        std::cerr << "  [-] Failed to rewind file descriptor.\n";
        return false;
    }

    uint64_t bytes_written = 0;
    while (bytes_written < size) {
        size_t current_chunk = static_cast<size_t>(std::min<uint64_t>(BUFFER_CHUNK_SIZE, size - bytes_written));

        if (is_zero_pass) {
            std::memset(buffer.data(), 0x00, current_chunk);
        } else {
            // Fill 64-bit random words for maximum throughput
            for (size_t i = 0; i < current_chunk; i += sizeof(uint64_t)) {
                uint64_t val = dist(prng);
                std::memcpy(buffer.data() + i, &val, std::min<size_t>(sizeof(uint64_t), current_chunk - i));
            }
        }

        ssize_t written = ::write(fd, buffer.data(), current_chunk);
        if (written <= 0) {
            std::cerr << "  [-] Write failure during pass at offset " << bytes_written << "\n";
            return false;
        }
        bytes_written += written;
    }

    // Force disk controller commit after every pass
    return dosync(fd);
}

bool FileShredder::do_wipefd(int fd, uint64_t target_size, const ShredConfig& config) {
    int total_passes = config.iterations + (config.zero_fill ? 1 : 0);

    // Run random data passes
    for (uint32_t i = 1; i <= config.iterations; ++i) {
        if (!dopass(fd, target_size, i, total_passes, false)) {
            return false;
        }
    }

    // Run final zero-fill pass to conceal the shred signature
    if (config.zero_fill) {
        if (!dopass(fd, target_size, total_passes, total_passes, true)) {
            return false;
        }
    }

    // Truncate file allocation to 0 bytes on disk
    if (::ftruncate(fd, 0) != 0) {
        std::cerr << "  [-] Warning: ftruncate to 0 failed.\n";
    }
    dosync(fd);

    return true;
}

bool FileShredder::wipename(const std::string& filepath) {
    fs::path orig(filepath);
    fs::path dir = orig.parent_path().empty() ? "." : orig.parent_path();
    std::string base = orig.filename().string();

    std::cout << "  [*] Scrubbing directory table metadata (inode entry obfuscation)...\n";

    // Repeatedly rename to progressively shorter sequences (e.g. 00000 -> 0000 -> 0)
    for (size_t len = base.length(); len > 0; --len) {
        std::string obf_name(len, NAMESET[0]);
        fs::path new_path = dir / obf_name;

        if (::rename(orig.c_str(), new_path.c_str()) == 0) {
            orig = new_path;
            sync_directory(dir.string()); // Commit modified directory slot to disk
        }
    }

    // Final unlink deletes an obfuscated dummy record
    if (::unlink(orig.c_str()) != 0) {
        std::cerr << "  [-] Failed to unlink final file.\n";
        return false;
    }

    sync_directory(dir.string());
    std::cout << "  [+] Directory record obliterated and unlinked.\n";
    return true;
}

bool FileShredder::shred_file(const std::string& filepath, const ShredConfig& config) {
    struct stat st;
    if (::stat(filepath.c_str(), &st) != 0) {
        std::cerr << "[-] Target file does not exist: " << filepath << "\n";
        return false;
    }

    // Validate target is a regular file (never attack sockets/pipes)
    if (!S_ISREG(st.st_mode)) {
        std::cerr << "[-] Safety: Target is not a regular file.\n";
        return false;
    }

    uint64_t wipe_size = static_cast<uint64_t>(st.st_size);

    // Slack space rounding from shred.c: round up to st_blksize to purge tail slack
    if (config.clear_slack && st.st_blksize > 0) {
        uint64_t remainder = wipe_size % st.st_blksize;
        if (remainder != 0) {
            wipe_size += (st.st_blksize - remainder);
            std::cout << "  [+] Slack space rounding: Adjusted target size to " 
                      << wipe_size << " bytes (Block size: " << st.st_blksize << ")\n";
        }
    }

    std::cout << "[*] Target identified: " << filepath << " (" << st.st_size << " bytes)\n";

    int fd = ::open(filepath.c_str(), O_WRONLY | O_SYNC);
    if (fd < 0) {
        // Fallback: Attempt chmod permissions bypass if writable bit is absent
        ::chmod(filepath.c_str(), S_IWUSR);
        fd = ::open(filepath.c_str(), O_WRONLY | O_SYNC);
        if (fd < 0) {
            std::cerr << "[-] Error opening file descriptor for writing.\n";
            return false;
        }
    }

    // Execute the overwrite passes
    bool wipe_ok = do_wipefd(fd, wipe_size, config);
    ::close(fd);

    if (!wipe_ok) {
        std::cerr << "[-] Shredding passes encountered an error.\n";
        return false;
    }

    // Obfuscate directory metadata and unlink
    if (config.remove) {
        return wipename(filepath);
    }

    return true;
}

} // namespace aegis::sanitizer