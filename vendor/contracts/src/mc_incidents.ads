-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Faults;
package MC_Incidents with SPARK_Mode, Pure is
   type Phase is
     (Open, Correlating, Containment_Required, Contained, Diagnosing,
      Repairing, Verifying, Closed, Escalated);
   type Event is
     (Observe_Fault, Confirm_Containment, Begin_Diagnosis, Begin_Repair,
      Record_Repair, Observe_Healthy, Escalate, Close_Incident);
   type State is record
      Incident_ID, Cluster_ID, Resource_ID : Identity := Zero_Identity;
      Policy, Cause, Containment_Receipt, Repair_Receipt : Digest := Zero_Digest;
      Revision, First_Observed, Last_Observed : Counter := 0;
      Fault_Count : Counter := 0;
      Healthy_Samples : Natural range 0 .. 255 := 0;
      Worst : MC_Faults.Severity := MC_Faults.Informational;
      Current : Phase := Open;
      Data_At_Risk, Execution_At_Risk : Boolean := False;
   end record;
   type Evidence is record
      Expected_Revision, Now : Counter := 0;
      Fault : MC_Faults.Fault;
      Correlation : Digest := Zero_Digest;
      Containment : Digest := Zero_Digest;
      Repair : Digest := Zero_Digest;
      Stable_For_Ms : Counter := 0;
      Required_Stable_Ms : Counter := 0;
      Authenticated, Ownership_Safe, Data_Consistent : Boolean := False;
      Dependencies_Healthy, No_Open_Severe_Faults : Boolean := False;
   end record;
   function Valid (S : State) return Boolean with Global => null;
   procedure Step
     (S : in out State; E : Event; X : Evidence; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then S = S'Old)
         and then (if Status = OK then S.Revision = S'Old.Revision + 1);
   -- Closing requires containment/repair evidence, fresh stable observations and
   -- no open severe fault. Time alone never clears an incident.
end MC_Incidents;
