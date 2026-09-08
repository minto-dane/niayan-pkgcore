-- SPDX-License-Identifier: MIT
package body MC_Recovery_Cohort with SPARK_Mode is
   function Quorum (W : Witnesses; Expected : Digest; Needed : Positive) return Boolean is
      Count : Natural := 0;
      Recovery, Independent : Boolean := False;
   begin
      if Is_Zero (Expected) or else W'Length > 32 or else Needed < 2 then return False; end if;
      for I in W'Range loop
         pragma Loop_Invariant(Count=I-W'First);
         if not W (I).Authenticated or else not W (I).Current or else
            W (I).Anchor_Hash /= Expected or else Is_Zero (W (I).Principal) or else
            Is_Zero (W (I).Domain_ID) then return False; end if;
         for J in W'First .. I - 1 loop
            if W (I).Principal = W (J).Principal or else W (I).Domain_ID = W (J).Domain_ID then return False; end if;
         end loop;
         Count := Count + 1;
         Recovery := Recovery or W (I).Recovery_Role;
         Independent := Independent or not W (I).Recovery_Role;
      end loop;
      return Count >= Needed and then Recovery and then Independent;
   end Quorum;
   function Usable (A : Anchor; E : Evidence) return Boolean is
   begin
      return not Is_Zero (A.Node) and then not Is_Zero (A.Recovery_ID) and then
         not Is_Zero (A.Manifest) and then not Is_Zero (A.Catalog) and then
         not Is_Zero (A.Journal_Head) and then not Is_Zero (A.Pending_Set) and then
         not Is_Zero (A.Cohort) and then A.Generation /= 0 and then
         A.Generation >= E.Minimum_Generation and then A.Trust_Epoch = E.Current_Trust
         and then A.Expires > E.Now and then E.Exact_Anchor and then E.Valid_Quorum
         and then E.External_Floor_Current and then E.Trust_Not_Rolled_Back
         and then (not E.Core_Suspect or else E.Rescue_Independent_And_Verified);
   end Usable;
   procedure Prepare (S : in out State; A : Anchor; E : Evidence; R : out Outcome) is
   begin
      R := Denied;
      if S.Status not in Uninspected | Quarantined or else not Usable (A, E)
         or else not E.Writer_Stopped or else not E.Evidence_Preserved or else
         not E.Storage_Healthy or else not E.Capacity_Reserved then return; end if;
      if S.Attempts = 16 or else S.Revision = Counter'Last then R := Exhausted; return; end if;
      S.Subject := A; S.Status := Reconstructing; S.Attempts := S.Attempts + 1;
      S.Outstanding_Effects := E.Pending_External_Effects;
      S.Revision := S.Revision + 1; R := OK;
   end Prepare;
   procedure Check_Candidate (S : in out State; E : Evidence; R : out Outcome) is
   begin
      R := Denied;
      if S.Status /= Reconstructing or else not Usable (S.Subject, E) or else
         not E.Writer_Stopped or else not E.Exact_Objects or else not E.Full_Inventory
         or else not E.Native_State_Validated or else not E.Exact_Journal_Head
         or else not E.Replay_Set_Preserved or else
         E.Pending_External_Effects /= S.Outstanding_Effects then return; end if;
      if S.Revision = Counter'Last then R := Exhausted; return; end if;
      S.Status := Candidate_Checked; S.Revision := S.Revision + 1; R := OK;
   end Check_Candidate;
   procedure Publish (S : in out State; E : Evidence; R : out Outcome) is
   begin
      R := Denied;
      if S.Status /= Candidate_Checked or else not Usable (S.Subject, E) or else
         not E.Writer_Stopped or else not E.Exact_Objects or else not E.Full_Inventory
         or else not E.Exact_Journal_Head or else not E.Replay_Set_Preserved
         or else not E.Native_State_Validated or else not E.Evidence_Preserved
         or else E.Pending_External_Effects /= S.Outstanding_Effects then return; end if;
      if S.Revision = Counter'Last then R := Exhausted; return; end if;
      S.Status := Reconciliation_Only; S.Revision := S.Revision + 1; R := OK;
   end Publish;
   procedure Accept_Operational (S : in out State; E : Evidence;
      Reconciled_Effects, Application_Acceptance, Independent_Approval : Boolean;
      R : out Outcome) is
   begin
      R := Denied;
      if S.Status /= Reconciliation_Only or else not Usable (S.Subject, E) or else
         not Reconciled_Effects or else not Application_Acceptance or else not Independent_Approval
         or else not E.Exact_Objects or else not E.Native_State_Validated or else
         not E.Full_Inventory or else not E.Exact_Journal_Head or else not E.Replay_Set_Preserved then return; end if;
      if S.Revision = Counter'Last then R := Exhausted; return; end if;
      S.Outstanding_Effects := 0; S.Status := Operational;
      S.Revision := S.Revision + 1; R := OK;
   end Accept_Operational;
end MC_Recovery_Cohort;
