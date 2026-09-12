-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with MC_Codec;
package body Pkg_Root_Handoff with SPARK_Mode => Off is
   function Result (Code : Interfaces.C.int) return Outcome is
     (case Code is when 0 => OK, when 1 => Denied, when 3 => Stale, when 4 => Conflict, when others => Indeterminate);
   procedure Open (C : in out Session; Supervisor_FD : Integer; Deadline : Counter; Status : out Outcome) is
      function Start (Handle : in out System.Address; FD : Interfaces.C.int;
         Deadline : Interfaces.C.unsigned_long_long) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_root_handoff_open";
   begin
      Status := Result (Start (C.Handle, Interfaces.C.int (Supervisor_FD), Interfaces.C.unsigned_long_long (Deadline)));
   exception when others => Close (C); Status := Indeterminate;
   end Open;
   procedure Prepare (C : in out Session; Generation, Root_Manifest, Archive, Worker : Digest;
      Stage : Identity; Size, Entries, Deadline : Counter;
      Archive_FD, Reservation_FD : Integer; Status : out Outcome) is
      function Send (Handle, Request : System.Address; Archive, Reservation : Interfaces.C.int) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_root_handoff_prepare";
      Wire : aliased Bytes (1 .. 192) := (others => 0);
   begin
      Wire (1 .. 8) := (78, 73, 65, 72, 78, 68, 48, 49);
      Wire (9 .. 40) := Generation; Wire (41 .. 72) := Root_Manifest;
      Wire (73 .. 104) := Archive; Wire (105 .. 136) := Worker; Wire (137 .. 152) := Stage;
      MC_Codec.Put64 (Wire, 153, Wide (Size)); MC_Codec.Put64 (Wire, 161, Wide (Entries));
      MC_Codec.Put64 (Wire, 169, Wide (Deadline));
      Status := Result (Send (C.Handle, Wire'Address, Interfaces.C.int (Archive_FD), Interfaces.C.int (Reservation_FD)));
   exception when others => Close (C); Status := Indeterminate;
   end Prepare;
   procedure Close (C : in out Session) is
      procedure Finish (Handle : in out System.Address)
        with Import, Convention => C, External_Name => "nia_root_handoff_close";
   begin Finish (C.Handle); end Close;
   overriding procedure Finalize (C : in out Session) is
   begin Close (C); end Finalize;
end Pkg_Root_Handoff;
