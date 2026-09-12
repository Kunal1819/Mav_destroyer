# Aegis Data Sanitization Suite

A verifiable forensic data sanitization suite engineered in C++20 for high-assurance data destruction. Aegis provides both granular file-level surgical shredding and block-level raw disk sanitization.

---

## Install c++ and nwipe

Install GCC with C++20 support and `nwipe`:

\\\bash
sudo dnf install -y gcc-c++ nwipe
\`\`\`

---

## Compilation

Build the unified CLI binary:

\`\`\`bash
g++ -std=c++20 -Iinclude src/sanitizer/file_shredder.cpp src/main_cli.cpp -o aegis_cli
\`\`\`

---

## Quickstart & Verification Guide

### 1. Surgical File Shredding

Create a dummy payload and destroy it:

\`\`\`bash
# Create dummy file
echo "SECRET_PAYLOAD_TEST_DATA" > confidential.txt

# Run the shredder
./aegis_cli shred confidential.txt

# Confirm file removal
ls confidential.txt
\`\`\`

---

### 2. Block-Level Sanitization (Loopback Sandbox)

To verify raw disk wiping safely without endangering the host OS, execute inside an isolated loop device:

\`\`\`bash
# 1. Create a 64MB sandbox disk image
dd if=/dev/urandom of=sandbox_disk.raw bs=1M count=64

# 2. Attach to a loop device
sudo losetup -fP sandbox_disk.raw
# (Check assigned device with: losetup -a)

# 3. Execute block wipe via Aegis (e.g., targeting /dev/loop0)
sudo ./aegis_cli wipe-disk /dev/loop0 --method zero

# 4. Forensically verify raw sectors (output will be pure 00s)
sudo hexdump -C -n 4096 /dev/loop0

# 5. Detach device when done
sudo losetup -d /dev/loop0
rm sandbox_disk.raw
\`\`\`

---

## Architecture & Security Gating

* **Host Protection:** The CLI hard-blocks any non-loop device (e.g., `/dev/sda`, `/dev/nvme0n1`) to prevent catastrophic partition loss in development environments.
* **Cross-Platform Readiness:** Core shredder logic leverages modern C++20 standard libraries with isolated OS abstractions for POSIX and Windows API.