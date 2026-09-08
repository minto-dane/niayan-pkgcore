-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Generation with SPARK_Mode, Pure is
   type Phase is (Proposed, Staged, Canary, Verified, Accepted, Committed, Rejected, Quarantined);
   type State is record
      Generation_ID, Previous_ID, Baseline, Recovery : Digest := Zero_Digest;
      Sequence, Revision, Entered_At : Counter := 0;
      Current : Phase := Proposed;
      Healthy_Samples : Natural range 0..255 := 0;
   end record;
   type Evidence is record
      Expected_Revision, Now, Minimum_Soak_Ms : Counter := 0;
      Baseline, Recovery : Digest := Zero_Digest;
      Stage_Verified, Canary_Healthy, Cluster_Healthy : Boolean := False;
      Recovery_Pinned, Incidents_Clear, Acceptance_Approved : Boolean := False;
      Commit_Approved, Independent_Reviewer : Boolean := False;
   end record;
   type Command is (Record_Staged, Begin_Canary, Observe_Healthy, Accept_Change, Commit, Reject, Quarantine);
   procedure Step(S:in out State; C:Command; E:Evidence; Status:out Outcome)
     with Global=>null,
       Post => (if Status/=OK then S=S'Old) and then (if Status=OK then S.Revision>S'Old.Revision);
end MC_Generation;
