-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with MC_Hex;
package body Pkg_Root_Session with SPARK_Mode => Off is
   use type System.Address;
   use type Interfaces.C.int;
   function Convert (Code : Interfaces.C.int) return Outcome is
     (case Code is when 0 => OK, when 1 => Denied, when 3 => Stale,
        when 4 => Conflict, when others => Indeterminate);
   procedure Open
     (C : in out Session; Socket_Path, Boot_ID : String;
      Generation, Root_Manifest, Archive, Worker, Device_Plan : Digest;
      Stage : Identity; Size, Entries, Deadline : Counter;
      Bank : Pkg_Root_Identity.Root_Identity;
      Archive_FD, Reservation_FD : Integer; Status : out Outcome) is
      function Start (Handle : in out System.Address;
         Path, G, R, A, W, ID, P, B : System.Address;
         Size, Entries, Deadline, Mount, Inode, Major, Minor : Interfaces.C.unsigned_long_long;
         Archive_FD, Reservation_FD : Interfaces.C.int;
         Root_Inode : out Interfaces.C.unsigned_long_long) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_root_session_open";
      Path : aliased constant String := Socket_Path & Character'Val (0);
      B : aliased constant String := Boot_ID & Character'Val (0);
      G : aliased constant String := MC_Hex.Encode (Generation) & Character'Val (0);
      R : aliased constant String := MC_Hex.Encode (Root_Manifest) & Character'Val (0);
      A : aliased constant String := MC_Hex.Encode (Archive) & Character'Val (0);
      W : aliased constant String := MC_Hex.Encode (Worker) & Character'Val (0);
      P : aliased constant String := MC_Hex.Encode (Device_Plan) & Character'Val (0);
      ID : aliased constant String := MC_Hex.Encode (Stage) & Character'Val (0);
      Inode : Interfaces.C.unsigned_long_long := 0;
   begin
      Status := Conflict;
      if C.Handle /= System.Null_Address then return; end if;
      C.Root := (Mount_ID => 0, Inode => 0, Device_Major => 0, Device_Minor => 0);
      Status := Invalid_Input;
      if Socket_Path'Length not in 1 .. 107 or else Socket_Path (Socket_Path'First) /= '/'
        or else (for some V of Socket_Path => V = Character'Val (0))
        or else Boot_ID'Length /= 36 or else (for some V of Boot_ID => V = Character'Val (0))
        or else Generation = Zero_Digest or else Root_Manifest = Zero_Digest
        or else Archive = Zero_Digest or else Worker = Zero_Digest or else Device_Plan = Zero_Digest
        or else Stage = Zero_Identity or else Archive_FD < 0 or else Reservation_FD < 0 then return; end if;
      Status := Convert (Start (C.Handle, Path'Address, G'Address, R'Address, A'Address, W'Address,
         ID'Address, P'Address, B'Address, Interfaces.C.unsigned_long_long (Size),
         Interfaces.C.unsigned_long_long (Entries), Interfaces.C.unsigned_long_long (Deadline),
         Interfaces.C.unsigned_long_long (Bank.Mount_ID), Interfaces.C.unsigned_long_long (Bank.Inode),
         Interfaces.C.unsigned_long_long (Bank.Device_Major), Interfaces.C.unsigned_long_long (Bank.Device_Minor),
         Interfaces.C.int (Archive_FD), Interfaces.C.int (Reservation_FD), Inode));
      if Status = OK then C.Root := Bank; C.Root.Inode := Wide (Inode); end if;
   exception when others => Finalize (C); Status := Indeterminate;
   end Open;
   procedure Observe
     (C : in out Session; Archive_FD, Reservation_FD : Integer; Status : out Outcome) is
      function Sample (Handle : System.Address; Archive_FD, Reservation_FD : Interfaces.C.int) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_root_session_observe";
   begin
      Status := Convert (Sample (C.Handle, Interfaces.C.int (Archive_FD), Interfaces.C.int (Reservation_FD)));
      if Status /= OK then C.Root := (Mount_ID => 0, Inode => 0, Device_Major => 0, Device_Minor => 0); end if;
   exception when others => Finalize (C); Status := Indeterminate;
   end Observe;
   function Held (C : Session) return Boolean is
      function Current (Handle : System.Address) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_root_session_held";
   begin
      return Current (C.Handle) = 1;
   end Held;
   function Observation (C : Session) return Pkg_Root_Identity.Root_Identity is
   begin
      if not Held (C) then return (Mount_ID => 0, Inode => 0, Device_Major => 0, Device_Minor => 0); end if;
      return C.Root;
   end Observation;
   procedure Close (C : in out Session; Status : out Outcome) is
      function Finish (Handle : in out System.Address) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_root_session_close";
   begin
      Status := Convert (Finish (C.Handle)); C.Root := (Mount_ID => 0, Inode => 0, Device_Major => 0, Device_Minor => 0);
   exception when others => Finalize (C); Status := Indeterminate;
   end Close;
   overriding procedure Finalize (C : in out Session) is
      procedure Discard (Handle : in out System.Address)
        with Import, Convention => C, External_Name => "nia_root_session_discard";
   begin
      Discard (C.Handle); C.Root := (Mount_ID => 0, Inode => 0, Device_Major => 0, Device_Minor => 0);
   end Finalize;
end Pkg_Root_Session;
