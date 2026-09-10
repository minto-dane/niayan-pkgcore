-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Transactions with SPARK_Mode is
   subtype Authorized_Command is Command range Validate_Plan..Record_Restored
     with Static_Predicate => Authorized_Command /= Begin_Reconcile;
   function Well_Formed (T : Transaction) return Boolean is
     (not Is_Zero (T.ID) and then not Is_Zero (T.Plan_Digest)
      and then T.Membership_Epoch > 0 and then T.Fence_Token > 0);
   function Write_Authorized (T : Transaction; E : Evidence) return Boolean is
     (Well_Formed (T) and then E.Authenticated_Authority
      and then E.Current_Quorum and then E.Exclusive_Fence
      and then E.Membership_Epoch = T.Membership_Epoch
      and then E.Fence_Token = T.Fence_Token
      and then E.Lease_Deadline > E.Now
      and then E.Bound_Plan = T.Plan_Digest
      and then E.Expected_Revision = T.Revision);
   procedure Step
     (T : in out Transaction; C : Command; E : Evidence;
      Action : out Effect; Status : out Outcome) is
      Next_Phase : Phase := T.Current;
      Next_Action : Effect := No_Effect;
      Permitted : Boolean := False;
   begin
      Action := No_Effect; Status := Denied;
      if not Well_Formed (T) then Status := Invalid_Input; return; end if;
      if T.Revision /= E.Expected_Revision then Status := Conflict; return; end if;
      if T.Revision = Counter'Last then Status := Exhausted; return; end if;
      if T.Current in Committed | Restored | Quarantined then return; end if;
      if C = Begin_Reconcile then
         if T.Current /= Empty then
            Next_Phase := Reconciling; Next_Action := Inspect_Actual_State;
            Permitted := True;
         end if;
      elsif C = Mark_Quarantined then
         -- Logical quarantine only. Stopping a cluster-owned service requires its owner.
         Next_Phase := Quarantined; Next_Action := Record_Quarantine; Permitted := True;
      elsif Write_Authorized (T, E) then
         case Authorized_Command(C) is
            when Validate_Plan =>
               Permitted := T.Current = Empty and then E.Plan_Checked
                 and then E.Observed_Generation = T.Base_Generation;
               Next_Phase := Validated;
            when Record_Staged =>
               Permitted := T.Current = Validated and then E.Staged_Verified
                 and then E.Recovery_Pinned and then E.Intent_Durable
                 and then E.Observed_Generation = T.Base_Generation;
               Next_Phase := Staged;
            when Record_Quiesced =>
               Permitted := T.Current = Staged and then E.Resource_Quiesced
                 and then E.No_Unknown_Effects and then E.Intent_Durable;
               Next_Phase := Quiesced;
            when Begin_Apply =>
               Permitted := T.Current = Quiesced and then E.Resource_Quiesced
                 and then E.Recovery_Pinned and then E.Staged_Verified and then E.Intent_Durable
                 and then E.No_Unknown_Effects
                 and then E.Observed_Generation = T.Base_Generation;
               Next_Phase := Applying; Next_Action := Apply_Files;
            when Record_Applied =>
               Permitted := T.Current = Applying and then E.Applied_Matches
                 and then E.No_Unknown_Effects and then E.Intent_Durable;
               Next_Phase := Applied;
            when Begin_Check =>
               Permitted := T.Current = Applied and then E.Intent_Durable;
               Next_Phase := Checking; Next_Action := Verify_Installed_State;
            when Record_Verified =>
               Permitted := T.Current = Checking and then E.Applied_Matches
                 and then E.Config_Valid and then E.Service_Healthy and then E.Intent_Durable
                 and then E.No_Unknown_Effects;
               Next_Phase := Verified;
            when Begin_Commit =>
               Permitted := T.Current = Verified and then E.Applied_Matches
                 and then E.Config_Valid and then E.Service_Healthy and then E.Intent_Durable
                 and then E.No_Unknown_Effects and then E.Recovery_Pinned;
               Next_Phase := Committing; Next_Action := Commit_Metadata;
            when Record_Committed =>
               Permitted := T.Current = Committing and then E.Commit_Durable
                 and then E.Applied_Matches and then E.No_Unknown_Effects;
               Next_Phase := Committed;
            when Begin_Restore =>
               Permitted := T.Current = Reconciling and then E.Rollback_Compatible
                 and then E.Resource_Quiesced and then E.Recovery_Pinned
                 and then E.Intent_Durable and then E.No_Unknown_Effects;
               Next_Phase := Restoring; Next_Action := Restore_Files;
            when Record_Restored =>
               Permitted := T.Current = Restoring and then E.Before_Matches
                 and then E.Config_Valid and then E.Intent_Durable and then E.No_Unknown_Effects;
               Next_Phase := Restored;
         end case;
      end if;
      if not Permitted then return; end if;
      T.Current := Next_Phase;
      T.Revision := T.Revision + 1;
      Action := Next_Action;
      Status := OK;
   end Step;
end Pkg_Transactions;
