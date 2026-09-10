-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Recovery_Catalog with SPARK_Mode, Pure is
   Max_Points : constant:=64;
   type Point is record
      ID,Root_ID : Identity:=Zero_Identity;
      Manifest,Package_Set : Digest:=Zero_Digest;
      Generation,Trust_Epoch,Data_Schema,Created_At,Verified_At : Counter:=0;
      Bytes_Required : Counter:=0;
      Authenticated,Artifacts_Present,Integrity_Checked,Restoration_Tested : Boolean:=False;
      Signing_Key_Revoked,Vulnerable_Disallowed : Boolean:=True;
      Active,Last_Accepted,Unresolved_Intent,Pinned_By_Operator : Boolean:=True;
   end record;
   type Points is array(Positive range 1..Max_Points) of Point;
   type Policy is record
      Root_ID : Identity:=Zero_Identity;
      Now,Oldest_Trust_Epoch,Maximum_Test_Age,Current_Data_Schema : Counter:=0;
      Minimum_Retained : Positive range 1..Max_Points:=2;
      Minimum_Age : Counter:=86_400;
      Allow_Data_Downgrade : Boolean:=False;
   end record;
   function Admissible(P : Policy; Item : Point) return Boolean with Global=>null;
   procedure Select_Point(P : Policy; Items : Points; Count : Natural;
      Selected : out Natural; Status : out Outcome) with Global=>null;
   function May_Prune(P : Policy; Items : Points; Count,Index : Natural) return Boolean with Global=>null;
   -- Decisions only: never deletes CAS, audit, trust, keys, or business data.
   -- Snapshot freshness/test receipts must be authenticated by external policy.
end Pkg_Recovery_Catalog;
