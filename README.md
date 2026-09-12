# Aegis Data Sanitization Suite

A verifiable forensic data sanitization suite engineered in C++20 for high-assurance data destruction. Aegis provides both granular file-level surgical shredding and block-level raw disk sanitization.

---

## Install C++ and nwipe

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

Create a dummy payload and destroy it:

```bash
echo "SECRET_PAYLOAD_TEST_DATA" > confidential.txt
./aegis_cli shred confidential.txt
ls confidential.txt
```

---

### 2. Block-Level Sanitization (Loopback Sandbox)

To verify raw disk wiping safely without endangering the host OS, execute inside an isolated loop device:

```bash
dd if=/dev/urandom of=sandbox_disk.raw bs=1M count=64
sudo losetup -fP sandbox_disk.raw
sudo ./aegis_cli wipe-disk /dev/loop0 --method zero
sudo hexdump -C -n 4096 /dev/loop0
sudo losetup -d /dev/loop0
rm sandbox_disk.raw
```

---

## Architecture & Security Gating

* **Host Protection:** The CLI hard-blocks any non-loop device (e.g., `/dev/sda`, `/dev/nvme0n1`) to prevent catastrophic partition loss in development environments.
* **Cross-Platform Readiness:** Core shredder logic leverages modern C++20 standard libraries with isolated OS abstractions for POSIX and Windows API.