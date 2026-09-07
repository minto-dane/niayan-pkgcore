-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Text; with Pkg_RPM; with Pkg_File_Plan;
package Pkg_Payload_Map with SPARK_Mode, Pure is
   Capacity : constant:=4_096;
   type Member is record
      Path, User_Name, Group_Name, Link_Target : MC_Text.Value;
      Kind : Pkg_File_Plan.Kind:=Pkg_File_Plan.Absent;
      Mode, Flags : Word:=0;
      Size : Counter:=0;
      Content : Digest:=Zero_Digest;
      Ghost : Boolean:=False;
   end record;
   type Member_Array is array(Positive range 1..Capacity) of Member;
   type Inventory is record Files : Member_Array; Count : Natural range 0..Capacity:=0; end record;
   procedure Decode(B : Bytes; M : Pkg_RPM.Metadata; Files : out Inventory; Status : out Outcome) with Global=>null;
   function Find(Files : Inventory; Path : String) return Natural with Global=>null;
   -- Maps actual RPM v4 file metadata; requires SHA256 for regular file contents.
   -- Ownership remains symbolic here. A site identity registry must resolve it.
end Pkg_Payload_Map;
