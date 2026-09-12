#include "sanitizer/file_shredder.hpp"
#include <iostream>
#include <vector>
#include <random>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <cerrno>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
#else
  #include <fcntl.h>
  #include <unistd.h>
  #include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace aegis::sanitizer {

static size_t get_platform_block_size(const std::string& path) {
#ifdef _WIN32
    WCHAR root_path[MAX_PATH];
    std::wstring wpath = fs::path(path).wstring();
    if (GetVolumePathNameW(wpath.c_str(), root_path, MAX_PATH)) {
        DWORD sectorsPerCluster = 0, bytesPerSector = 0, freeClusters = 0, totalClusters = 0;
        if (GetDiskFreeSpaceW(root_path, &sectorsPerCluster, &bytesPerSector, &freeClusters, &totalClusters)) {
            return static_cast<size_t>(sectorsPerCluster * bytesPerSector);
        }
    }
    return 4096;
#else
    struct stat st;
    if (::stat(path.c_str(), &st) == 0 && st.st_blksize > 0) {
        return static_cast<size_t>(st.st_blksize);
    }
    return 4096;
#endif
}

static bool flush_hardware_buffers(
#ifdef _WIN32
    HANDLE handle
#else
    int fd
#endif
) {
#ifdef _WIN32
    return FlushFileBuffers(handle) != 0;
#else
    return ::fdatasync(fd) == 0;
#endif
}

bool FileShredder::shred_file(const std::string& filepath, const ShredConfig& config) {
    if (!fs::exists(filepath)) {
        std::cerr << "[-] Target does not exist: " << filepath << "\n";
        return false;
    }

    std::uintmax_t raw_size = fs::file_size(filepath);
    size_t block_size = get_platform_block_size(filepath);

    std::uintmax_t target_size = raw_size;
    if (config.clear_slack && block_size > 0) {
        std::uintmax_t remainder = raw_size % block_size;
        if (remainder != 0) {
            target_size = raw_size + (block_size - remainder);
            std::cout << "  [+] Slack space rounding: Adjusted target size to " 
                      << target_size << " bytes (Block size: " << block_size << ")\n";
        }
    }

    std::cout << "[*] Target identified: " << filepath << " (" << raw_size << " bytes)\n";

#ifdef _WIN32
    std::wstring wpath = fs::path(filepath).wstring();
    HANDLE handle = CreateFileW(
        wpath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        NULL
    );

    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Error: Failed to open file handle on Windows (Error: " << GetLastError() << ")\n";
        return false;
    }
#else
    int fd = ::open(filepath.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) {
        std::cerr << "[-] Error opening file: " << std::strerror(errno) << "\n";
        return false;
    }
#endif

    const size_t chunk_size = 64 * 1024;
    std::vector<uint8_t> buffer(chunk_size);
    std::mt19937_64 rng(std::random_device{}());

    for (size_t pass = 1; pass <= config.iterations; ++pass) {
        std::cout << "  [*] Pass " << pass << "/" 
                  << (config.zero_fill ? config.iterations + 1 : config.iterations) 
                  << " [PRNG Chaos Pattern]...\n";

#ifdef _WIN32
        LARGE_INTEGER li;
        li.QuadPart = 0;
        SetFilePointerEx(handle, li, NULL, FILE_BEGIN);
#else
        ::lseek(fd, 0, SEEK_SET);
#endif

        std::uintmax_t bytes_written = 0;
        while (bytes_written < target_size) {
            size_t to_write = std::min<std::uintmax_t>(chunk_size, target_size - bytes_written);

            size_t* word_ptr = reinterpret_cast<size_t*>(buffer.data());
            size_t words = to_write / sizeof(size_t);
            for (size_t i = 0; i < words; ++i) {
                word_ptr[i] = rng();
            }

#ifdef _WIN32
            DWORD written = 0;
            if (!WriteFile(handle, buffer.data(), static_cast<DWORD>(to_write), &written, NULL)) {
                std::cerr << "[-] Windows write failure on pass " << pass << "\n";
                CloseHandle(handle);
                return false;
            }
            bytes_written += written;
#else
            ssize_t res = ::write(fd, buffer.data(), to_write);
            if (res < 0) {
                std::cerr << "[-] POSIX write failure on pass " << pass << ": " << std::strerror(errno) << "\n";
                ::close(fd);
                return false;
            }
            bytes_written += res;
#endif
        }

#ifdef _WIN32
        flush_hardware_buffers(handle);
#else
        flush_hardware_buffers(fd);
#endif
    }

    if (config.zero_fill) {
        std::cout << "  [*] Pass " << config.iterations + 1 << "/" 
                  << config.iterations + 1 << " [Zero Fill 0x00]...\n";

        std::fill(buffer.begin(), buffer.end(), 0x00);

#ifdef _WIN32
        LARGE_INTEGER li;
        li.QuadPart = 0;
        SetFilePointerEx(handle, li, NULL, FILE_BEGIN);
#else
        ::lseek(fd, 0, SEEK_SET);
#endif

        std::uintmax_t bytes_written = 0;
        while (bytes_written < target_size) {
            size_t to_write = std::min<std::uintmax_t>(chunk_size, target_size - bytes_written);
#ifdef _WIN32
            DWORD written = 0;
            WriteFile(handle, buffer.data(), static_cast<DWORD>(to_write), &written, NULL);
            bytes_written += written;
#else
            ssize_t res = ::write(fd, buffer.data(), to_write);
            bytes_written += res;
#endif
        }

#ifdef _WIN32
        flush_hardware_buffers(handle);
#else
        flush_hardware_buffers(fd);
#endif
    }

#ifdef _WIN32
    CloseHandle(handle);
#else
    ::close(fd);
#endif

    // 3. Metadata Obfuscation & File Removal
    if (config.remove) {
        std::cout << "  [*] Scrubbing directory table metadata (inode entry obfuscation)...\n";
        
        fs::path p(filepath);
        fs::path parent_dir = p.parent_path();
        std::string current_name = p.filename().string();

        for (size_t i = 0; i < current_name.length(); ++i) {
            std::string temp_name = std::string(current_name.length() - i, '0' + (i % 10));
            fs::path new_path = parent_dir.empty() ? fs::path(temp_name) : parent_dir / temp_name;
            fs::path old_path = parent_dir.empty() ? fs::path(current_name) : parent_dir / current_name;
            
            std::error_code ec;
            fs::rename(old_path, new_path, ec);
            if (!ec) {
                current_name = temp_name;
            }
        }

        fs::path final_path = parent_dir.empty() ? fs::path(current_name) : parent_dir / current_name;
        std::error_code ec;
        fs::remove(final_path, ec);
        if (!ec) {
            std::cout << "  [+] Directory record obliterated and unlinked.\n";
        }
    }

    return true;
}

} // namespace aegis::sanitizer