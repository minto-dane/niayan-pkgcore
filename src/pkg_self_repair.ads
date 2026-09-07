-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Time_Guard; with Pkg_Inventory; with Pkg_File_Plan;
package Pkg_Self_Repair with SPARK_Mode, Pure is
   type Finding is record
      Known : Boolean := False;
      Actual : Pkg_File_Plan.Shape;
   end record;
   type Finding_Array is array(Positive range 1..Pkg_Inventory.Max_Entries) of Finding;
   type Policy is record
      Root_ID : Identity := Zero_Identity;
      Inventory_Digest : Digest := Zero_Digest;
      Maximum_Changes : Positive range 1..Pkg_File_Plan.Max_Changes := 8;
      Maximum_Bytes : Counter := 64*1_024*1_024;
      Maximum_Age_Ms : Counter := 5_000;
      Allow_Missing_Files : Boolean := False;
   end record;
   type Context is record
      Root_ID, Transaction_ID, Boot_ID : Identity := Zero_Identity;
      Generation, Epoch, Fence, Now : Counter := 0;
      Inventory_Digest : Digest := Zero_Digest;
      Stamp : MC_Time_Guard.Stamp;
      Authenticated_Baseline, Ownership_Exclusive, Quiesced : Boolean := False;
      Capacity_Sufficient, Recovery_Artifacts_Verified : Boolean := False;
      Intrusion_Suspected, Hardware_Fault_Suspected, Pending_Change, Maintenance : Boolean := True;
   end record;
   procedure Build(P : Policy; C : Context; Baseline : Pkg_Inventory.Manifest;
      Observed : Finding_Array; Result : out Pkg_File_Plan.Plan;
      Changed, Blocked : out Natural; Status : out Outcome) with Global=>null,
      Post=>(if Status=OK and then Changed>0 then Pkg_File_Plan.Layout_Valid(Result));
   -- Proposal only. The resulting exact-preimage plan must be admitted, signed,
   -- and executed through the ordinary package WAL/CAS/gate engine. No bypass.
   -- A single unknown or excluded drift blocks automatic repair of the batch.
end Pkg_Self_Repair;
