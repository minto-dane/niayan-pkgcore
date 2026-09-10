-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Log_Format;
with Pkg_File_Plan;
package Pkg_File_Replay with SPARK_Mode, Pure is
   -- Semantics of persisted file transaction records. NOT a filesystem executor.
   -- A decoded record's checksum is integrity framing, not origin authentication.
   Prepared       : constant := 1;
   Apply_Intent   : constant := 2;
   Apply_Done     : constant := 3;
   Applied        : constant := 4;
   Commit_Intent  : constant := 5;
   Committed      : constant := 6;
   Restore_Intent : constant := 7;
   Restore_Done   : constant := 8;
   Restored       : constant := 9;
   Tail_Repaired  : constant := 10; -- legacy, before terminal only

   type Direction is (Forward, Reverse_Change, Ready_To_Commit,
                      Commit_Pending, Forward_Final, Reverse_Final);
   type Binding is record
      Root_ID, Transaction_ID : Identity := Zero_Identity;
      Plan_Digest : Digest := Zero_Digest;
      Epoch, Fence, Target_Generation : Counter := 0;
      Changes : Natural range 0 .. Pkg_File_Plan.Max_Changes := 0;
   end record;
   type View is record
      Phase : Direction := Forward;
      Next_Index : Natural range 0 .. Pkg_File_Plan.Max_Changes + 1 := 1;
      Pending_Index : Natural range 0 .. Pkg_File_Plan.Max_Changes := 0;
      Receipt : Digest := Zero_Digest;
      Records : Counter := 0;
      Last_Digest : Digest := Zero_Digest;
   end record;
   function Valid (B : Binding) return Boolean with Global => null;
   function Valid (B : Binding; V : View) return Boolean with Global => null;
   procedure Consume (B : Binding; E : MC_Log_Format.Log_Entry;
                      V : in out View; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then V = V'Old)
         and then (if Status = OK then Valid (B,V));
   function Image_Allowed (B : Binding; V : View; Index : Positive;
                           Matches_Before, Matches_After : Boolean) return Boolean
     with Global => null;
   -- Call only with freshly captured, plan-bound image comparisons. Finished
   -- forward entries must be AFTER; untouched future entries must be BEFORE.
   -- A pending intent may be either. Unknown contents are never admissible.
end Pkg_File_Replay;
