-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_Transactions with SPARK_Mode, Pure is
   type Phase is
     (Empty, Validated, Staged, Quiesced, Applying, Applied, Checking,
      Verified, Committing, Committed, Reconciling, Restoring, Restored, Quarantined);
   type Command is
     (Validate_Plan, Record_Staged, Record_Quiesced, Begin_Apply, Record_Applied,
      Begin_Check, Record_Verified, Begin_Commit, Record_Committed,
      Begin_Reconcile, Begin_Restore, Record_Restored, Mark_Quarantined);
   type Effect is
     (No_Effect, Inspect_Actual_State, Apply_Files, Verify_Installed_State,
      Commit_Metadata, Restore_Files, Record_Quarantine);
   type Transaction is record
      ID : Identity := Zero_Identity;
      Plan_Digest : Digest := Zero_Digest;
      Base_Generation : Counter := 0;
      Membership_Epoch : Counter := 0;
      Fence_Token : Counter := 0;
      Revision : Counter := 0;
      Current : Phase := Empty;
   end record;
   type Evidence is record
      Expected_Revision : Counter := 0;
      Observed_Generation : Counter := 0;
      Membership_Epoch : Counter := 0;
      Fence_Token : Counter := 0;
      Now : Counter := 0;
      Lease_Deadline : Counter := 0;
      Bound_Plan : Digest := Zero_Digest;
      Authenticated_Authority : Boolean := False;
      Current_Quorum : Boolean := False;
      Exclusive_Fence : Boolean := False;
      Plan_Checked : Boolean := False;
      Recovery_Pinned : Boolean := False;
      Staged_Verified : Boolean := False;
      Resource_Quiesced : Boolean := False;
      Intent_Durable : Boolean := False;
      Applied_Matches : Boolean := False;
      Config_Valid : Boolean := False;
      Service_Healthy : Boolean := False;
      Commit_Durable : Boolean := False;
      Rollback_Compatible : Boolean := False;
      Before_Matches : Boolean := False;
      No_Unknown_Effects : Boolean := False;
   end record;
   function Well_Formed (T : Transaction) return Boolean with Global => null;
   function Write_Authorized (T : Transaction; E : Evidence) return Boolean
     with Global => null;
   procedure Step
     (T : in out Transaction; C : Command; E : Evidence;
      Action : out Effect; Status : out Outcome)
     with Global => null,
       Post =>
         (if Status /= OK then T = T'Old and then Action = No_Effect)
         and then
         (if Action in Apply_Files | Commit_Metadata | Restore_Files then
             Write_Authorized (T'Old, E) and then E.Intent_Durable)
         and then
         (if Status = OK then T.Revision > T'Old.Revision
            and then T.ID = T'Old.ID and then T.Plan_Digest = T'Old.Plan_Digest
            and then T.Base_Generation = T'Old.Base_Generation
            and then T.Membership_Epoch = T'Old.Membership_Epoch
            and then T.Fence_Token = T'Old.Fence_Token);
   -- Evidence is adapter-produced, never accepted as unauthenticated packet booleans.
   -- A returned effect is a proposal to a qualified durable executor, not an RPC.
end Pkg_Transactions;
