-- SPDX-License-Identifier: MIT
-- Explicit, not production-audited ABI boundary, Linux x86-64 / glibc, 64-bit off_t/time_t only.
with Interfaces.C; with System;
package MC_Posix with SPARK_Mode => Off is
   use Interfaces.C;
   subtype FD is int;
   Invalid_FD : constant FD := -1;
   O_RDONLY : constant int := 0; O_WRONLY : constant int := 1;
   O_RDWR : constant int := 2; O_CREAT : constant int := 64;
   O_EXCL : constant int := 128; O_NONBLOCK : constant int := 2_048;
   O_DIRECTORY : constant int := 65_536; O_NOFOLLOW : constant int := 131_072;
   O_CLOEXEC : constant int := 524_288; O_PATH : constant int := 2_097_152;
   AT_FDCWD : constant int := -100; AT_SYMLINK_NOFOLLOW : constant int := 256;
   AT_REMOVEDIR : constant int := 512; AT_EMPTY_PATH : constant int := 4_096;
   LOCK_EX_NB : constant int := 6;
   ENOENT : constant int := 2; EINTR : constant int := 4;
   EAGAIN : constant int := 11; EEXIST : constant int := 17;
   ENODATA : constant int := 61;
   function Open (P : System.Address; Flags : int; Mode : unsigned) return FD
     with Import, Convention => C, External_Name => "open";
   function Openat (D : FD; P : System.Address; Flags : int; Mode : unsigned) return FD
     with Import, Convention => C, External_Name => "openat";
   function Close (F : FD) return int with Import, Convention => C, External_Name => "close";
   function Dup (F : FD; Cmd : int; Arg : int) return int
     with Import, Convention => C, External_Name => "fcntl";
   function Read (F : FD; B : System.Address; N : size_t) return long
     with Import, Convention => C, External_Name => "read";
   function Pread (F : FD; B : System.Address; N : size_t; Offset : long) return long
     with Import, Convention => C, External_Name => "pread";
   function Write (F : FD; B : System.Address; N : size_t) return long
     with Import, Convention => C, External_Name => "write";
   function Fsync (F : FD) return int with Import, Convention => C, External_Name => "fsync";
   function Ftruncate (F : FD; N : long) return int
     with Import, Convention => C, External_Name => "ftruncate";
   function Lseek (F : FD; N : long; W : int) return long
     with Import, Convention => C, External_Name => "lseek";
   function Flock (F : FD; Operation : int) return int
     with Import, Convention => C, External_Name => "flock";
   function Euid return unsigned with Import, Convention => C, External_Name => "geteuid";
   function Egid return unsigned with Import, Convention => C, External_Name => "getegid";
   function Errno_Location return access int
     with Import, Convention => C, External_Name => "__errno_location";
   function Statx (D : FD; P : System.Address; Flags : int; Mask : unsigned;
                   B : System.Address) return int
     with Import, Convention => C, External_Name => "statx";
   function Renameat2 (D1 : FD; N1 : System.Address; D2 : FD; N2 : System.Address;
                       Flags : unsigned) return int
     with Import, Convention => C, External_Name => "renameat2";
   function Unlinkat (D : FD; Name : System.Address; Flags : int) return int
     with Import, Convention => C, External_Name => "unlinkat";
   function Mkdirat (D : FD; Name : System.Address; Mode : unsigned) return int
     with Import, Convention => C, External_Name => "mkdirat";
   function Symlinkat (Target : System.Address; D : FD; Name : System.Address) return int
     with Import, Convention => C, External_Name => "symlinkat";
   function Readlinkat (D : FD; Name, B : System.Address; N : size_t) return long
     with Import, Convention => C, External_Name => "readlinkat";
   function Fchmod (F : FD; Mode : unsigned) return int
     with Import, Convention => C, External_Name => "fchmod";
   function Fchown (F : FD; UID, GID : unsigned) return int
     with Import, Convention => C, External_Name => "fchown";
   function Fchownat (D : FD; Name : System.Address; UID, GID : unsigned; Flags : int) return int
     with Import, Convention => C, External_Name => "fchownat";
   function Flistxattr (F : FD; B : System.Address; N : size_t) return long
     with Import, Convention => C, External_Name => "flistxattr";
   function Fgetxattr (F : FD; Name, B : System.Address; N : size_t) return long
     with Import, Convention => C, External_Name => "fgetxattr";
   function Fsetxattr (F : FD; Name, B : System.Address; N : size_t; Flags : int) return int
     with Import, Convention => C, External_Name => "fsetxattr";
   function Fremovexattr (F : FD; Name : System.Address) return int
     with Import, Convention => C, External_Name => "fremovexattr";
   type Timespec is record Sec, Nsec : long := 0; end record with Convention => C;
   type Timespec_Pair is array (0 .. 1) of Timespec with Convention => C;
   function Futimens (F : FD; Times : System.Address) return int
     with Import, Convention => C, External_Name => "futimens";
   function Clock_Gettime (ID : int; T : access Timespec) return int
     with Import, Convention => C, External_Name => "clock_gettime";
   type Open_How is record Flags, Mode, Resolve : unsigned_long := 0; end record
     with Convention => C;
   function Openat2_Call (Number : long; D : int; P, How : System.Address; N : size_t) return long
     with Import, Convention => C, External_Name => "syscall";
end MC_Posix;
