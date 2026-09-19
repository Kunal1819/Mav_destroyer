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
g++ -std=c++20 -Iinclude src/sanitizer/file_shredder.cpp src/sanitizer/platform_fs_posix.cpp src/main_cli.cpp -o aegis_cli
```

---

## Quickstart & Verification Guide

### 1. Surgical File Shredding

Aegis operates directly on raw filesystem blocks, making it completely format-agnostic. It shreds any file type (media, PDFs, executables, databases, disk images) using multi-pass PRNG overwrites, cluster slack-space clearance, hardware sync, and inode scrubbing.

#### Target Any Real File
```bash
# Shred documents, media, databases, or binaries
./aegis_cli shred /path/to/financial_report.pdf
./aegis_cli shred /path/to/database.sqlite
./aegis_cli shred /path/to/system_dump.img
./aegis_cli shread /path/to that file --recursive method= --audit.json 

# Custom profile: 7 chaotic PRNG passes without final zero-fill
./aegis_cli shred confidential.docx --passes 7 --no-zero
```

* **Default Behavior (no flags):** 3 passes of high-entropy PRNG noise + 1 final pass of pure zeros (`0x00`).
* **`--passes N`:** Overrides the number of PRNG overwrite rounds.
* **`--no-zero`:** Skips the final zero-fill pass, leaving high-entropy random data in the blocks.

#### Quick Test Run (Dummy Verification)
```bash
# Create dummy test file
echo "SECRET_PAYLOAD_TEST_DATA" > dummy_test.txt

# Shred dummy file
./aegis_cli shred dummy_test.txt

# Verify removal
ls dummy_test.txt
```

---

### 2. Block-Level Drive Sanitization

#### Option A: Isolated Loopback Device (Testing Sandbox)

Ideal for safe, non-destructive verification:

```bash
# 1. Create a 64MB raw sandbox disk image
dd if=/dev/urandom of=sandbox_disk.raw bs=1M count=64

# 2. Attach to a loop device
sudo losetup -fP sandbox_disk.raw
# (Check assigned device node via: losetup -a)

# 3. Wipe the loop device (no --force needed for loop devices)
sudo ./aegis_cli wipe-disk /dev/loop0 --method zero

# 4. Forensically verify block zero (outputs all 00s)
sudo hexdump -C -n 4096 /dev/loop0

# 5. Clean up
sudo losetup -d /dev/loop0
rm sandbox_disk.raw
```

#### Option B: Physical USB Drive Sanitization

Targeting physical drives requires explicit target validation and the `--force` flag:

```bash
# 1. Carefully verify your USB device node
lsblk

# 2. Execute block wipe with the mandatory --force flag
sudo ./aegis_cli wipe-disk /dev/sdb --force --method zero

# Supported methods: zero, dod522022m, gutmann
```

---

## Safety Architecture & System Protection

Aegis applies automated system checks before initiating raw block wipes:

* **Host OS Lockout:** Automatically parses `/proc/mounts` and `/proc/swaps`. If a target device contains active host partitions (`/`, `/boot`, `/boot/efi`, `/home`, `/usr`, `/var`, or active swap), the operation is halted immediately.
* **Physical Media Guard:** Physical non-loop storage nodes (e.g., `/dev/sdX`, `/dev/nvmeXn1`) are locked by default unless the explicit `--force` flag is provided.
* **Hardware Cache Flushing:** Enforces physical storage controller flushes via `fdatasync` (POSIX) and `FlushFileBuffers` (Win32) after every overwrite pass.