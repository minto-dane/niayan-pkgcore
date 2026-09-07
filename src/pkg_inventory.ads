-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Text; with Pkg_File_Plan;
package Pkg_Inventory with SPARK_Mode, Pure is
   Max_Entries : constant := 1_024;
   Maximum_Encoding : constant := 4_500_000;
   type Inventory_Item is record
      Path : MC_Text.Value;
      Desired : Pkg_File_Plan.Shape;
      Domain : Pkg_File_Plan.State_Domain := Pkg_File_Plan.Packaged_Files;
      Allow_Automatic_Repair : Boolean := False;
      Boot_Or_Security_Critical : Boolean := True;
   end record;
   type Entry_Array is array (Positive range 1..Max_Entries) of Inventory_Item;
   type Manifest is record
      Root_ID : Identity := Zero_Identity;
      Generation : Counter := 0;
      Package_Set, Contract : Digest := Zero_Digest;
      Count : Natural range 0..Max_Entries := 0;
      Items : Entry_Array;
   end record;
   function Valid(M : Manifest) return Boolean with Global=>null;
   function Automatic_Path(Path : String) return Boolean with Global=>null;
   function Fingerprint(M : Manifest) return Digest with Global=>null, Pre=>Valid(M);
   procedure Encode(M : Manifest; B : out Bytes; Used : out Natural; Status : out Outcome) with Global=>null;
   procedure Decode(B : Bytes; M : out Manifest; Status : out Outcome) with Global=>null;
   -- Inventory is an explicitly scoped accepted baseline, not an entire-host claim.
   -- It must be authenticated by the site's admission authority. A digest supplied
   -- by the same untrusted source as the bytes is not authentication.
end Pkg_Inventory;
