-- SPDX-License-Identifier: MIT
package body MC_Incidents with SPARK_Mode is
   function Valid (S : State) return Boolean is
     (S.Incident_ID /= Zero_Identity and then S.Cluster_ID /= Zero_Identity
      and then S.Resource_ID /= Zero_Identity and then S.Policy /= Zero_Digest
      and then S.Revision > 0 and then S.First_Observed > 0
      and then S.Last_Observed >= S.First_Observed
      and then (if S.Current >= Contained then S.Containment_Receipt /= Zero_Digest)
      and then (if S.Current >= Verifying and then S.Current /= Escalated
                then S.Repair_Receipt /= Zero_Digest));
   procedure Step
     (S : in out State; E : Event; X : Evidence; Status : out Outcome) is
      N : State := S;
   begin
      Status := Denied;
      if not Valid (S) or else X.Expected_Revision /= S.Revision
        or else S.Revision = Counter'Last or else X.Now < S.Last_Observed
        or else not X.Authenticated
      then return; end if;
      case E is
         when Observe_Fault =>
            if not MC_Faults.Valid (X.Fault)
              or else X.Fault.Cluster_ID /= S.Cluster_ID
              or else X.Fault.Resource_ID /= S.Resource_ID
              or else X.Fault.Observed_At < S.Last_Observed
            then Status := Invalid_Input; return; end if;
            N.Last_Observed := X.Fault.Observed_At;
            if N.Fault_Count = Counter'Last then Status := Exhausted; return; end if;
            N.Fault_Count := N.Fault_Count + 1;
            N.Worst := MC_Faults.Worse (N.Worst, X.Fault.Level);
            N.Data_At_Risk := N.Data_At_Risk or else X.Fault.Data_At_Risk;
            N.Execution_At_Risk := N.Execution_At_Risk or else X.Fault.Execution_At_Risk;
            if X.Correlation /= Zero_Digest then N.Cause := X.Correlation; end if;
            if MC_Faults.Isolation_Required (X.Fault) then
               N.Current := Containment_Required;
            elsif N.Current = Open then N.Current := Correlating; end if;
            N.Healthy_Samples := 0;
         when Confirm_Containment =>
            if S.Current not in Containment_Required | Correlating
              or else X.Containment = Zero_Digest or else not X.Ownership_Safe
            then return; end if;
            N.Containment_Receipt := X.Containment; N.Current := Contained;
         when Begin_Diagnosis =>
            if S.Current not in Contained | Correlating then return; end if;
            N.Current := Diagnosing;
         when Begin_Repair =>
            if S.Current not in Diagnosing | Contained or else X.Repair = Zero_Digest then return; end if;
            N.Repair_Receipt := X.Repair; N.Current := Repairing;
         when Record_Repair =>
            if S.Current /= Repairing or else X.Repair = Zero_Digest then return; end if;
            N.Repair_Receipt := X.Repair; N.Current := Verifying; N.Healthy_Samples := 0;
         when Observe_Healthy =>
            if S.Current /= Verifying or else not X.Data_Consistent
              or else not X.Dependencies_Healthy or else not X.Ownership_Safe
              or else not X.No_Open_Severe_Faults
            then return; end if;
            if X.Stable_For_Ms < X.Required_Stable_Ms then
               N.Healthy_Samples := Natural'Min (255, N.Healthy_Samples + 1);
            else
               N.Healthy_Samples := Natural'Min (255, N.Healthy_Samples + 1);
            end if;
         when Escalate =>
            N.Current := Escalated;
         when Close_Incident =>
            if S.Current /= Verifying or else S.Healthy_Samples < 3
              or else X.Stable_For_Ms < X.Required_Stable_Ms
              or else not X.Data_Consistent or else not X.Dependencies_Healthy
              or else not X.Ownership_Safe or else not X.No_Open_Severe_Faults
              or else S.Containment_Receipt = Zero_Digest or else S.Repair_Receipt = Zero_Digest
            then return; end if;
            N.Current := Closed;
      end case;
      N.Revision := S.Revision + 1;
      if X.Now > N.Last_Observed then N.Last_Observed := X.Now; end if;
      S := N; Status := OK;
   end Step;
end MC_Incidents;
