# Aegis Data Sanitization Suite

A verifiable forensic data sanitization suite engineered in C++20 for high-assurance data destruction. Aegis provides both granular file-level surgical shredding and block-level raw disk sanitization.

---

## Install Prerequisites (Fedora Setup)

Install GCC with C++20 support and `nwipe`:

```bash
sudo dnf install -y gcc-c++ nwipe
```

---

## Compilation

Build the unified CLI binary:

```bash
g++ -std=c++20 -Iinclude src/sanitizer/file_shredder.cpp src/main_cli.cpp -o aegis_cli
```

---

## Quickstart & Verification Guide

### 1. Surgical File Shredding

Wipe files across any format (executables, media, documents, databases) using 3-pass PRNG noise, final zero-fill, slack-space rounding, and directory table scrubbing:

```bash
# Create dummy test file
echo "SECRET_PAYLOAD_TEST_DATA" > confidential.txt

# Execute surgical shredding
./aegis_cli shred confidential.txt

# Confirm file unlinked
ls confidential.txt
```

---

### 2. Block-Level Drive Sanitization

#### Option A: Isolated Loopback Device (Testing Sandbox)

Ideal for quick development and verification without physical storage:

```bash
# 1. Create a 64MB raw sandbox disk image
dd if=/dev/urandom of=sandbox_disk.raw bs=1M count=64

# 2. Mount to a loop device
sudo losetup -fP sandbox_disk.raw
# (Check assigned node via: losetup -a)

# 3. Wipe the loop device (no --force needed for loopback)
sudo ./aegis_cli wipe-disk /dev/loop0 --method zero

# 4. Forensically verify block zero (will output pure 00s)
sudo hexdump -C -n 4096 /dev/loop0

# 5. Clean up
sudo losetup -d /dev/loop0
rm sandbox_disk.raw
```

#### Option B: Physical USB Drive Sanitization

Physical drives require target verification and explicit authorization:

```bash
# 1. Identify your USB device node carefully (e.g., /dev/sdb)
lsblk

# 2. Execute block wipe with the mandatory --force flag
sudo ./aegis_cli wipe-disk /dev/sdb --force --method zero

# Supported methods: zero, dod522022m, gutmann
```

---

## Safety Architecture & System Protection

Aegis implements strict kernel and filesystem safety gates before executing any low-level block write:

* **Host OS Lockout:** Queries `/proc/mounts` and `/proc/swaps` prior to execution. If a target drive contains active host mounts (`/`, `/boot`, `/boot/efi`, `/home`, `/usr`, `/var`, or active swap), the operation is halted immediately to protect host system integrity.
* **Physical Media Guard:** Physical non-loop storage nodes (e.g., `/dev/sdX`, `/dev/nvmeXn1`) are blocked by default unless the explicit `--force` argument is supplied.
* **Hardware Cache Flushing:** Enforces physical storage controller flushes via `fdatasync` (POSIX) and `FlushFileBuffers` (Win32) after every overwrite pass.