-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Recovery_Cohort with SPARK_Mode, Pure is
   type Phase is (Uninspected, Quarantined, Reconstructing, Candidate_Checked,
      Reconciliation_Only, Operational);
   type Anchor is record
      Node, Recovery_ID : Identity := Zero_Identity;
      Manifest, Catalog, Journal_Head, Pending_Set, Cohort : Digest := Zero_Digest;
      Generation, Trust_Epoch, Last_Sequence, Expires : Counter := 0;
   end record;
   type Witness is record
      Principal, Domain_ID : Identity := Zero_Identity;
      Anchor_Hash : Digest := Zero_Digest;
      Authenticated, Current, Recovery_Role : Boolean := False;
   end record;
   type Witnesses is array (Positive range <>) of Witness;
   function Quorum (W : Witnesses; Expected : Digest; Needed : Positive) return Boolean
      with Global => null;
   type Evidence is record
      Exact_Anchor, Valid_Quorum, External_Floor_Current : Boolean := False;
      Core_Suspect, Rescue_Independent_And_Verified : Boolean := False;
      Writer_Stopped, Evidence_Preserved, Storage_Healthy, Capacity_Reserved : Boolean := False;
      Exact_Objects, Full_Inventory, Native_State_Validated : Boolean := False;
      Exact_Journal_Head, Replay_Set_Preserved, Trust_Not_Rolled_Back : Boolean := False;
      Pending_External_Effects : Natural := 0;
      Current_Trust, Minimum_Generation, Now : Counter := 0;
   end record;
   type State is record
      Subject : Anchor;
      Status : Phase := Uninspected;
      Revision : Counter := 0;
      Attempts : Natural range 0 .. 16 := 0;
      Outstanding_Effects : Natural := 0;
   end record;
   function Usable (A : Anchor; E : Evidence) return Boolean with Global => null;
   procedure Prepare (S : in out State; A : Anchor; E : Evidence; R : out Outcome)
      with Global => null;
   procedure Check_Candidate (S : in out State; E : Evidence; R : out Outcome)
      with Global => null;
   procedure Publish (S : in out State; E : Evidence; R : out Outcome)
      with Global => null, Post => (if R = OK then S.Status = Reconciliation_Only);
   procedure Accept_Operational (S : in out State; E : Evidence;
      Reconciled_Effects, Application_Acceptance, Independent_Approval : Boolean;
      R : out Outcome) with Global => null,
      Post => (if R = OK then S.Status = Operational and Reconciled_Effects
         and Application_Acceptance and Independent_Approval);
   -- Every fact is bound to the exact anchor by a qualified adapter. Persist
   -- accepted transitions before effects. Never infer lost history from mtimes
   -- or an installed file set. Trust floors and application data are not reset.
end MC_Recovery_Cohort;
