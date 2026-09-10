-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Kernel_Read with SPARK_Mode => Off is
   type Item is (Boot_ID, PID_One, Cgroup_Controllers, Kernel_Lockdown,
      SELinux_Enforce, BPF_Disabled, Kptr_Restrict, Dmesg_Restrict,
      ASLR_Mode, Modules_Disabled, Kernel_Release, Secure_Boot, Setup_Mode,
      Memory_Pressure, IO_Pressure);
   procedure Read (Source : Item; Data : out Bytes; Used : out Natural;
                   Status : out Outcome);
   -- Fixed Linux kernel-owned paths only; no caller-supplied filename, no writes.
   -- Reads to EOF, not st_size: procfs files commonly report size zero.
   -- openat2(NO_SYMLINKS|NO_MAGICLINKS|BENEATH), nonblocking, bounded data/EINTR.
   -- Inspection in the caller's mount/PID namespaces, not hardware attestation.
end MC_Kernel_Read;
