-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Acceptance with SPARK_Mode, Pure is
   type Phase is (Trial, Verified, Accepted, Committed, Rejected, Quarantined);
   type Action is (Observe, Accept_Change, Commit, Reject, Quarantine);
   type State is record
      Transaction_ID : Identity := Zero_Identity;
      Plan, Installed_Image, Recovery_Image : Digest := Zero_Digest;
      Revision, Applied_At, Last_Observed : Counter := 0;
      Healthy_Samples : Natural range 0 .. 255 := 0;
      Current : Phase := Trial;
   end record;
   type Evidence is record
      Expected_Revision, Now, Minimum_Trial_Ms : Counter := 0;
      Installed_Image, Recovery_Image : Digest := Zero_Digest;
      Holds_Clear, Integrity_OK, Configuration_OK, Service_OK : Boolean := False;
      No_Open_Incidents, Recovery_Pinned, Acceptance_Authorized : Boolean := False;
      Commit_Authorized : Boolean := False;
   end record;
   function Valid (S : State) return Boolean with Global => null;
   procedure Step (S : in out State; A : Action; E : Evidence; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then S = S'Old)
         and then (if Status = OK then S.Revision = S'Old.Revision + 1);
   -- APPLY and ACCEPT are deliberately distinct. A trial may run for days without
   -- becoming the baseline; COMMIT only permits recovery data to become GC-eligible.
end Pkg_Acceptance;
