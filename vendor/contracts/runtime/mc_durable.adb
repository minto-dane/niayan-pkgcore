-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with System; with MC_Paths;
package body MC_Durable with SPARK_Mode => Off is
   use Interfaces.C;
   use type Word; use type Wide; use type Byte;
   use type System.Bit_Order;
   O_RDONLY : constant int := 0;
   O_RDWR : constant int := 2;
   O_CREAT : constant int := 64;
   O_NOCTTY : constant int := 256;
   O_NONBLOCK : constant int := 2_048;
   O_CLOEXEC : constant int := 524_288;
   O_NOFOLLOW : constant int := 131_072;
   O_DIRECTORY : constant int := 65_536;
   LOCK_EX_NB : constant int := 6;
   AT_EMPTY_PATH : constant int := 4_096;
   function C_Open (Path : System.Address; Flags : int; Mode : unsigned) return int
     with Import, Convention => C, External_Name => "open";
   function C_Openat (FD : int; Path : System.Address; Flags : int; Mode : unsigned) return int
     with Import, Convention => C, External_Name => "openat";
   function C_Close (FD : int) return int
     with Import, Convention => C, External_Name => "close";
   function C_Flock (FD, Operation : int) return int
     with Import, Convention => C, External_Name => "flock";
   function C_Fsync (FD : int) return int
     with Import, Convention => C, External_Name => "fsync";
   function C_Lseek (FD : int; Offset : long; Whence : int) return long
     with Import, Convention => C, External_Name => "lseek";
   function C_Pread (FD : int; Buffer : System.Address; Count : size_t; Offset : long) return long
     with Import, Convention => C, External_Name => "pread";
   function C_Write (FD : int; Buffer : System.Address; Count : size_t) return long
     with Import, Convention => C, External_Name => "write";
   function C_Euid return unsigned
     with Import, Convention => C, External_Name => "geteuid";
   function C_Statx
     (FD : int; Path : System.Address; Flags : int; Mask : unsigned;
      Buffer : System.Address) return int
     with Import, Convention => C, External_Name => "statx";
   type Stat_Buffer is array (Natural range 0 .. 255) of Byte;
   for Stat_Buffer'Alignment use 8;
   function LE32 (B : Stat_Buffer; P : Natural) return Word is
     (Word (B(P)) + Word (B(P+1))*256 + Word(B(P+2))*65_536 + Word(B(P+3))*16_777_216);
   function LE64 (B : Stat_Buffer; P : Natural) return Wide is
     (Wide(LE32(B,P)) + Wide(LE32(B,P+4))*2**32);
   procedure Stat
     (FD : int; Need_Directory : Boolean; Length : out Counter; Status : out Outcome) is
      B : aliased Stat_Buffer := (others => 0);
      Empty_Path : aliased char_array := To_C ("");
      Mode, Mask : Word;
      Required : constant Word := 16#20F#; -- TYPE,MODE,NLINK,UID,SIZE
   begin
      Length := 0; Status := Unsupported;
      if long'Size /= 64 or else size_t'Size /= 64 or else System.Word_Size /= 64
        or else System.Default_Bit_Order /= System.Low_Order_First
      then return; end if;
      Status := IO_Error;
      if C_Statx (FD, Empty_Path'Address, AT_EMPTY_PATH, 16#7FF#, B'Address) /= 0 then return; end if;
      Mask := LE32 (B,0);
      if (Mask and Required) /= Required then Status := Unsupported; return; end if;
      Mode := Word (B(28)) + Word (B(29))*256;
      Status := Denied;
      if LE32 (B,20) /= Word (C_Euid) or else (Mode and 8#077#) /= 0 then return; end if;
      if Need_Directory then
         if (Mode and 8#170000#) /= 8#040000#
           or else (Mode and 8#7777#) /= 8#700# then return; end if;
      else
         if (Mode and 8#170000#) /= 8#100000# or else LE32 (B,16) /= 1
           or else ((Mode and 8#7777#) /= 8#600# and (Mode and 8#7777#) /= 8#400#)
         then return; end if;
      end if;
      if LE64(B,40) > Wide(Counter'Last) then Status := Exhausted; return; end if;
      Length := Counter (LE64(B,40)); Status := OK;
   end Stat;
   procedure Open_Private_Directory
     (Path : String; Handle : in out Directory_Handle; Status : out Outcome) is
      FD, Next_FD, Ignored : int;
      Start : Positive;
      Length : Counter;
      Root : aliased char_array := To_C ("/");
   begin
      Status := Invalid_Input;
      if Handle.FD /= -1 then Status := Conflict; return; end if;
      if Path'Length < 2 or else Path'Length > 4096 or else Path'Last = Integer'Last
        or else Path(Path'First) /= '/'
        or else not MC_Paths.Safe_Relative (Path(Path'First+1 .. Path'Last))
      then return; end if;
      FD := C_Open (Root'Address, O_RDONLY+O_DIRECTORY+O_NOFOLLOW+O_CLOEXEC,0);
      if FD < 0 then Status := IO_Error; return; end if;
      Start := Path'First+1;
      for J in Path'First+1 .. Path'Last+1 loop
         if J = Path'Last+1 or else Path(J) = '/' then
            declare
               Part : aliased char_array := To_C(Path(Start .. J-1));
            begin
               Next_FD := C_Openat(FD,Part'Address,O_RDONLY+O_DIRECTORY+O_NOFOLLOW+O_CLOEXEC,0);
            end;
            Ignored := C_Close(FD);
            if Next_FD < 0 then Status := IO_Error; return; end if;
            FD := Next_FD;
            if J <= Path'Last then Start := J+1; end if;
         end if;
      end loop;
      Stat (FD, True, Length, Status);
      if Status /= OK then Ignored := C_Close(FD); return; end if;
      Handle.FD := Integer(FD);
   end Open_Private_Directory;
   procedure Open_File
     (Directory : Directory_Handle; Name : String; Write_Mode : Boolean;
      Handle : in out File_Handle; Status : out Outcome) is
      Flags : int := O_RDONLY+O_CLOEXEC+O_NOFOLLOW+O_NONBLOCK+O_NOCTTY;
      Path : aliased char_array := To_C(Name);
      FD, Ignored : int;
      Length : Counter;
   begin
      Status := Invalid_Input;
      if Handle.FD /= -1 then Status := Conflict; return; end if;
      if Directory.FD < 0 or else not MC_Paths.Safe_Component(Name) then return; end if;
      if Write_Mode then Flags := O_RDWR+O_CREAT+O_CLOEXEC+O_NOFOLLOW+O_NONBLOCK+O_NOCTTY; end if;
      FD := C_Openat(int(Directory.FD),Path'Address,Flags,8#600#);
      if FD < 0 then Status := IO_Error; return; end if;
      Stat(FD,False,Length,Status);
      if Status /= OK then Ignored := C_Close(FD); return; end if;
      if C_Flock(FD,LOCK_EX_NB) /= 0 then
         Ignored := C_Close(FD); Status := Conflict; return;
      end if;
      if Write_Mode and then C_Fsync(int(Directory.FD)) /= 0 then
         Ignored := C_Close(FD); Status := IO_Error; return;
      end if;
      Handle.FD := Integer(FD); Handle.Writable := Write_Mode;
      Handle.Poisoned := False; Status := OK;
   end Open_File;
   procedure Open_Journal
     (Directory : Directory_Handle; Name : String;
      Handle : in out File_Handle; Status : out Outcome) is
   begin Open_File(Directory,Name,True,Handle,Status); end Open_Journal;
   procedure Open_Readonly
     (Directory : Directory_Handle; Name : String;
      Handle : in out File_Handle; Status : out Outcome) is
   begin Open_File(Directory,Name,False,Handle,Status); end Open_Readonly;
   procedure Size (Handle : File_Handle; Length : out Counter; Status : out Outcome) is
   begin
      Length := 0; Status := Invalid_Input;
      if Handle.FD < 0 or else Handle.Poisoned then return; end if;
      Stat(int(Handle.FD),False,Length,Status);
   end Size;
   procedure Read_At
     (Handle : File_Handle; Offset : Counter; Data : out Bytes; Status : out Outcome) is
      Done : Natural := 0;
      N : long;
   begin
      Data := (others => 0); Status := Invalid_Input;
      if Handle.FD < 0 or else Handle.Poisoned or else Data'Length > 16_777_216
        or else Offset > Counter'Last-Counter(Data'Length)
      then return; end if;
      while Done < Data'Length loop
         N := C_Pread(int(Handle.FD),Data(Data'First+Done)'Address,
                      size_t(Data'Length-Done),long(Offset+Counter(Done)));
         if N <= 0 or else N > long(Data'Length-Done) then
            Data := (others => 0); Status := IO_Error; return;
         end if;
         Done := Done+Natural(N);
      end loop;
      Status := OK;
   end Read_At;
   procedure Append
     (Handle : in out File_Handle; Expected_Size : Counter;
      Data : Bytes; Status : out Outcome) is
      Done : Natural := 0;
      At_End, N : long;
   begin
      Status := Invalid_Input;
      if Handle.FD < 0 or else not Handle.Writable or else Handle.Poisoned
        or else Data'Length = 0 or else Data'Length > 16_777_216
        or else Expected_Size > Counter'Last-Counter(Data'Length)
      then return; end if;
      At_End := C_Lseek(int(Handle.FD),0,2);
      if At_End < 0 then Status := IO_Error; return; end if;
      if Counter(At_End) /= Expected_Size then Status := Conflict; return; end if;
      while Done < Data'Length loop
         N := C_Write(int(Handle.FD),Data(Data'First+Done)'Address,size_t(Data'Length-Done));
         if N <= 0 or else N > long(Data'Length-Done) then
            Handle.Poisoned := True; Status := Indeterminate; return;
         end if;
         Done := Done+Natural(N);
      end loop;
      if C_Fsync(int(Handle.FD)) /= 0 then
         Handle.Poisoned := True; Status := Indeterminate; return;
      end if;
      Status := OK;
   end Append;
   procedure Close (Handle : in out File_Handle; Status : out Outcome) is
      R : int;
   begin
      Status := OK;
      if Handle.FD >= 0 then
         R := C_Close(int(Handle.FD));
         if R /= 0 then Status := IO_Error; end if;
      end if;
      Handle.FD := -1; Handle.Writable := False; Handle.Poisoned := False;
   end Close;
   procedure Close (Handle : in out Directory_Handle; Status : out Outcome) is
      R : int;
   begin
      Status := OK;
      if Handle.FD >= 0 then
         R := C_Close(int(Handle.FD));
         if R /= 0 then Status := IO_Error; end if;
      end if;
      Handle.FD := -1;
   end Close;
end MC_Durable;
