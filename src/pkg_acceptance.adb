-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Acceptance with SPARK_Mode is
   function Valid (S : State) return Boolean is
     (S.Transaction_ID /= Zero_Identity and then S.Plan /= Zero_Digest
      and then S.Installed_Image /= Zero_Digest and then S.Recovery_Image /= Zero_Digest
      and then S.Revision > 0 and then S.Applied_At > 0 and then S.Last_Observed >= S.Applied_At);
   procedure Step (S : in out State; A : Action; E : Evidence; Status : out Outcome) is
      N : State := S;
      Healthy : constant Boolean := E.Holds_Clear and then E.Integrity_OK
        and then E.Configuration_OK and then E.Service_OK and then E.No_Open_Incidents;
   begin
      Status := Denied;
      if not Valid (S) or else E.Expected_Revision /= S.Revision or else S.Revision = Counter'Last
        or else E.Now < S.Last_Observed or else E.Installed_Image /= S.Installed_Image
        or else E.Recovery_Image /= S.Recovery_Image
      then return; end if;
      case A is
         when Observe =>
            if S.Current not in Trial | Verified then return; end if;
            if Healthy then
               N.Healthy_Samples := Natural'Min (255, N.Healthy_Samples + 1);
               if N.Healthy_Samples >= 3 and then E.Now - S.Applied_At >= E.Minimum_Trial_Ms then N.Current := Verified; end if;
            else N.Healthy_Samples := 0; N.Current := Trial; end if;
         when Accept_Change =>
            if S.Current /= Verified or else not Healthy or else not E.Acceptance_Authorized
              or else not E.Recovery_Pinned or else E.Now - S.Applied_At < E.Minimum_Trial_Ms
            then return; end if;
            N.Current := Accepted;
         when Commit =>
            if S.Current /= Accepted or else not Healthy or else not E.Commit_Authorized then return; end if;
            N.Current := Committed;
         when Reject =>
            if S.Current in Committed | Quarantined then return; end if;
            if not E.Recovery_Pinned then return; end if;
            N.Current := Rejected;
         when Quarantine =>
            N.Current := Quarantined;
      end case;
      N.Last_Observed := E.Now; N.Revision := S.Revision + 1; S := N; Status := OK;
   end Step;
end Pkg_Acceptance;
