# Linux Hardening & Security Checklist

This document details the hardening baseline verified by the AEGIS Security Skill.

---

## 1. System Memory & Kernel Protections
* **ASLR (Address Space Layout Randomization)**:
  * Check: `/proc/sys/kernel/randomize_va_space`
  * Value `2` is required for full randomization (stack, VDSO, heap, BSS).
  * Fix: `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`
* **Dmesg Restrictions**:
  * Ensure non-root users cannot read kernel dmesg (`kernel.dmesg_restrict = 1`).

---

## 2. File Permissions & Access Controls
* **Critical Passwd & Shadow**:
  * `/etc/passwd`: Permissions should be `644`, owned by `root:root` (never world-writable).
  * `/etc/shadow`: Permissions should be `640` (or `600`), readable only by `root:shadow`.
* **SSH Key Hygiene**:
  * `~/.ssh/`: Permissions `700`.
  * `~/.ssh/id_*` (Private keys): Permissions `600` strictly.

---

## 3. SUID & Privilege Escalation Vectors
* SUID binaries execute with the privileges of the file owner (usually root).
* Any binary listed in [GTFOBins](https://gtfobins.github.io/) (such as `python`, `nmap`, `vim`, `find`, `bash`) must NEVER have the SUID bit set unless strictly isolated.
* Remediation:
  ```bash
  sudo chmod u-s <risky_binary>
  ```

---

## 4. Network Exposure & SSH Hardening
* **Listening Interfaces**:
  * Services meant for internal IPC or database backends (Redis, PostgreSQL, MySQL) must bind to `127.0.0.1` or unix domain sockets, NOT `0.0.0.0`.
* **SSH Daemon (`/etc/ssh/sshd_config`)**:
  * `PermitRootLogin no`
  * `PasswordAuthentication no` (prefer ED25519 public key authentication)
  * `X11Forwarding no` (unless explicitly required)
