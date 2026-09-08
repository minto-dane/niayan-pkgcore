-- SPDX-License-Identifier: MIT
package body MC_Generation with SPARK_Mode is
   procedure Step(S:in out State; C:Command; E:Evidence; Status:out Outcome) is
      N:State:=S;
      procedure Done is begin N.Revision:=N.Revision+1; S:=N; Status:=OK; end Done;
   begin
      Status:=Conflict;
      if S.Generation_ID=Zero_Digest or else S.Baseline=Zero_Digest or else S.Recovery=Zero_Digest or else S.Sequence=0
        or else E.Expected_Revision/=S.Revision or else S.Revision=Counter'Last or else E.Now<S.Entered_At then return; end if;
      if C=Quarantine then N.Current:=Quarantined; N.Entered_At:=E.Now; Done; return; end if;
      if C=Reject and then S.Current not in Committed | Rejected then
         if E.Recovery=S.Recovery and then E.Recovery_Pinned then N.Current:=Rejected; N.Entered_At:=E.Now; Done; end if; return;
      end if;
      case S.Current is
         when Proposed =>
            if C=Record_Staged and then E.Stage_Verified and then E.Baseline=S.Baseline
              and then E.Recovery=S.Recovery and then E.Recovery_Pinned
            then N.Current:=Staged; N.Entered_At:=E.Now; Done; end if;
         when Staged =>
            if C=Begin_Canary and then E.Incidents_Clear then N.Current:=Canary; N.Entered_At:=E.Now; N.Healthy_Samples:=0; Done; end if;
         when Canary =>
            if C=Observe_Healthy and then E.Canary_Healthy and then E.Cluster_Healthy and then E.Incidents_Clear
              and then N.Healthy_Samples<255
            then N.Healthy_Samples:=N.Healthy_Samples+1; if N.Healthy_Samples>=3 and then E.Now-S.Entered_At>=E.Minimum_Soak_Ms then N.Current:=Verified; N.Entered_At:=E.Now; end if; Done; end if;
         when Verified =>
            if C=Accept_Change and then E.Acceptance_Approved and then E.Independent_Reviewer and then E.Recovery_Pinned
            then N.Current:=Accepted; N.Entered_At:=E.Now; Done; end if;
         when Accepted =>
            if C=Commit and then E.Commit_Approved and then E.Independent_Reviewer and then E.Incidents_Clear
            then N.Current:=Committed; N.Entered_At:=E.Now; Done; end if;
         when Committed | Rejected | Quarantined => null;
      end case;
   end Step;
end MC_Generation;
