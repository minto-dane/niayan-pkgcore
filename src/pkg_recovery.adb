-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Recovery with SPARK_Mode is
   use Pkg_Transactions;
   function Decide
     (P : Phase; Actual : Observed_State; E : Recovery_Evidence) return Recovery_Action is
   begin
      if not E.Log_Valid or else not E.Trusted_Anchor_Valid or else not E.Root_Identity_Valid
        or else Actual = Unreadable or else P = Quarantined
      then return Quarantine; end if;
      if not E.External_Effects_Known then return Reconcile_External; end if;
      if P = Committed then
         if Actual = After_Image and then E.Commit_Confirmed and then E.After_Admissible then
            return Leave_Unchanged;
         end if;
         return Quarantine;
      end if;
      if P = Restored then
         if Actual = Before_Image and then E.Before_Admissible then return Leave_Unchanged; end if;
         return Quarantine;
      end if;
      if Actual = Before_Image then
         if P in Empty | Validated | Staged | Quiesced
           and then E.Before_Admissible
         then return Leave_Unchanged; end if;
      elsif Actual = After_Image and then E.After_Admissible then
         if P = Committing and then E.Commit_Confirmed then return Finish_Commit; end if;
         if P in Applying | Applied | Checking | Verified | Committing | Reconciling then
            return Revalidate_After;
         end if;
      end if;
      if E.Before_Pinned and then E.Before_Admissible and then E.Data_Backward_Compatible
        and then E.External_Effects_Known and then E.Exclusive_Writer and then E.Resource_Quiesced
      then return Restore_Before; end if;
      return Quarantine;
   end Decide;
end Pkg_Recovery;
