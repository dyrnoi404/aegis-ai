# Linux Hardening & Binary Mitigation Baseline (CIS Benchmark & John Erickson Model)

This document details the hardening baseline enforced by the AEGIS Security Framework.

---

## 1. Binary Mitigation Audit (Checksec Subsystem)
All production and system-critical binaries must be compiled with modern exploit mitigations:
* **NX / DEP (No-Execute Stack)**:
  * Verification: Program Header `PT_GNU_STACK` must lack `PF_X` execution flags.
  * GCC flag: `-z noexecstack` (prevents linear stack buffer execution).
* **Stack Canaries**:
  * Verification: Symbol references to `__stack_chk_fail`.
  * GCC flag: `-fstack-protector-strong` or `-fstack-protector-all`.
* **Position Independent Executable (PIE)**:
  * Verification: ELF type `ET_DYN` (shared object format with entry point).
  * GCC flag: `-fPIE -pie` (allows full binary address randomization under ASLR).
* **Full RELRO (Read-Only Relocations)**:
  * Verification: Program Header `PT_GNU_RELRO` present + `DT_BIND_NOW` dynamic flag.
  * GCC flag: `-Wl,-z,relro,-z,now` (makes GOT/PLT read-only after link-time resolution).

---

## 2. Kernel & Memory Parameters (Sysctl)
* **ASLR (randomize_va_space)**:
  * Baseline: `kernel.randomize_va_space = 2`
  * Rationale: Full randomization of stack, VDSO, shared libraries, and brk heap.
* **SUID Core Dumps (suid_dumpable)**:
  * Baseline: `fs.suid_dumpable = 0`
  * Rationale: Prevents unprivileged core dumping of setuid/privileged processes to extract passwords.
* **Kernel Pointers (kptr_restrict)**:
  * Baseline: `kernel.kptr_restrict = 2`
  * Rationale: Hides `%pK` kernel memory pointers from all unprivileged processes.
* **Dmesg Buffer Access (dmesg_restrict)**:
  * Baseline: `kernel.dmesg_restrict = 1`
  * Rationale: Blocks unprivileged users from reading hardware/kernel ring buffers.

---

## 3. Privilege Escalation & Capabilities
* **SUID/SGID Binaries**:
  * Any binary listed in [GTFOBins](https://gtfobins.github.io/) must NEVER carry the setuid flag:
    ```bash
    sudo chmod u-s /path/to/binary
    ```
* **Linux Capabilities**:
  * Inspect file capabilities:
    ```bash
    getcap -r /usr/bin /bin 2>/dev/null
    ```
  * Revoke excessive capabilities:
    ```bash
    setcap -r /path/to/binary
    ```

---

## 4. Network Exposure & SSH Daemon
* **Localhost Binding**:
  * Internal services (PostgreSQL, Redis, MySQL) must bind exclusively to `127.0.0.1` or unix domain sockets.
* **SSHD Configuration (`/etc/ssh/sshd_config`)**:
  * `PermitRootLogin prohibit-password` or `no`
  * `PasswordAuthentication no`
  * `X11Forwarding no`
