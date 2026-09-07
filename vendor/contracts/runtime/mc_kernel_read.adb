-- SPDX-License-Identifier: MIT
with Interfaces.C; with MC_Posix;
package body MC_Kernel_Read with SPARK_Mode => Off is
   use Interfaces.C; use MC_Posix;
   function Path (Source : Item) return String is
     (case Source is
      when Boot_ID => "proc/sys/kernel/random/boot_id",
      when PID_One => "proc/1/comm",
      when Cgroup_Controllers => "sys/fs/cgroup/cgroup.controllers",
      when Kernel_Lockdown => "sys/kernel/security/lockdown",
      when SELinux_Enforce => "sys/fs/selinux/enforce",
      when BPF_Disabled => "proc/sys/kernel/unprivileged_bpf_disabled",
      when Kptr_Restrict => "proc/sys/kernel/kptr_restrict",
      when Dmesg_Restrict => "proc/sys/kernel/dmesg_restrict",
      when ASLR_Mode => "proc/sys/kernel/randomize_va_space",
      when Modules_Disabled => "proc/sys/kernel/modules_disabled",
      when Kernel_Release => "proc/sys/kernel/osrelease",
      when Secure_Boot => "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
      when Setup_Mode => "sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c",
      when Memory_Pressure => "proc/pressure/memory",
      when IO_Pressure => "proc/pressure/io");
   procedure Read (Source : Item; Data : out Bytes; Used : out Natural;
                   Status : out Outcome) is
      Top : aliased char_array := To_C ("/");
      Name : aliased char_array := To_C (Path (Source));
      How : aliased Open_How :=
        (Flags => unsigned_long (O_RDONLY + O_CLOEXEC + O_NOFOLLOW + O_NONBLOCK),
         Mode => 0, Resolve => 14);
      D, F : int := -1; R : long; N : long;
      Scratch : aliased Bytes (1 .. 4097); Want : Natural;
      Interruptions : Natural := 0;
      procedure Drop (Handle : in out int) is
         Ignore : int; pragma Unreferenced (Ignore);
      begin
         if Handle >= 0 then Ignore := MC_Posix.Close (Handle); end if;
         Handle := -1;
      end Drop;
   begin
      Data := (others => 0); Used := 0; Status := Invalid_Input;
      if Data'Length = 0 or else Data'Length > 4096 then return; end if;
      D := MC_Posix.Open (Top'Address,O_RDONLY+O_DIRECTORY+O_CLOEXEC+O_NOFOLLOW,0);
      if D < 0 then Status := IO_Error; return; end if;
      R := Openat2_Call (437,D,Name'Address,How'Address,Open_How'Size/8);
      Drop (D);
      if R < 0 or else R > long (int'Last) then Status := IO_Error; return; end if;
      F := int (R);
      loop
         -- Always ask for one extra byte at capacity, to distinguish EOF from
         -- truncation. No fstat size assumption for procfs/sysfs/efivarfs.
         Want := Natural'Min (Scratch'Length,Data'Length-Used+1);
         N := MC_Posix.Read (F,Scratch'Address,size_t (Want));
         if N = 0 then Status := OK; exit;
         elsif N < 0 then
            if Errno_Location.all = EINTR and then Interruptions < 16 then
               Interruptions := Interruptions+1;
            else Status := IO_Error; exit; end if;
         elsif N > long (Data'Length-Used) then Status := Exhausted; exit;
         else
            for J in 1 .. Natural (N) loop Data (Data'First+Used+J-1) := Scratch (J); end loop;
            Used := Used+Natural (N);
         end if;
      end loop;
      Drop (F);
      if Status /= OK then Data := (others => 0); Used := 0; end if;
   exception
      when others => Drop (D); Drop (F); Data := (others => 0); Used := 0; Status := IO_Error;
   end Read;
end MC_Kernel_Read;
