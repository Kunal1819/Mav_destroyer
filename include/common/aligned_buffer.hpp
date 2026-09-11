#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <span>

namespace aegis::common {

class AlignedBuffer {
public:
    static constexpr size_t DEFAULT_ALIGNMENT = 4096;

    explicit AlignedBuffer(size_t size, size_t alignment = DEFAULT_ALIGNMENT)
        : size_(size), alignment_(alignment), data_(nullptr) 
    {
        if (size == 0) {
            throw std::invalid_argument("Buffer size must be greater than zero.");
        }
        void* ptr = nullptr;
        int res = ::posix_memalign(&ptr, alignment_, size_);
        if (res != 0 || !ptr) {
            throw std::bad_alloc();
        }
        data_ = static_cast<uint8_t*>(ptr);
    }

    ~AlignedBuffer() {
        if (data_) {
            ::free(data_);
            data_ = nullptr;
        }
    }

    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;

    AlignedBuffer(AlignedBuffer&& other) noexcept 
        : size_(other.size_), alignment_(other.alignment_), data_(other.data_) 
    {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    AlignedBuffer& operator=(AlignedBuffer&& other) noexcept {
        if (this != &other) {
            if (data_) ::free(data_);
            data_ = other.data_;
            size_ = other.size_;
            alignment_ = other.alignment_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    [[nodiscard]] uint8_t* data() noexcept { return data_; }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] size_t size() const noexcept { return size_; }
    [[nodiscard]] size_t alignment() const noexcept { return alignment_; }

private:
    size_t size_;
    size_t alignment_;
    uint8_t* data_;
};

} // namespace aegis::common