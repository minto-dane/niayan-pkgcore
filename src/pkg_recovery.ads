-- SPDX-License-Identifier: MIT
with Pkg_Transactions;
package Pkg_Recovery with SPARK_Mode, Pure is
   type Observed_State is (Before_Image, After_Image, Mixed_Image, Unreadable);
   type Recovery_Action is
     (Leave_Unchanged, Revalidate_After, Finish_Commit, Restore_Before,
      Reconcile_External, Quarantine);
   type Recovery_Evidence is record
      Log_Valid, Trusted_Anchor_Valid, Root_Identity_Valid : Boolean := False;
      Before_Pinned, Before_Admissible, After_Admissible : Boolean := False;
      External_Effects_Known, Data_Backward_Compatible : Boolean := False;
      Exclusive_Writer, Resource_Quiesced, Commit_Confirmed : Boolean := False;
   end record;
   function Decide
     (P : Pkg_Transactions.Phase; Actual : Observed_State;
      E : Recovery_Evidence) return Recovery_Action
     with Global => null,
       Post => (if Decide'Result = Restore_Before then E.Before_Pinned
          and then E.Before_Admissible and then E.Data_Backward_Compatible
          and then E.External_Effects_Known and then E.Exclusive_Writer and then E.Resource_Quiesced);
end Pkg_Recovery;
