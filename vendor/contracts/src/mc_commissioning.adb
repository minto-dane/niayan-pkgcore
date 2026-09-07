-- SPDX-License-Identifier: MIT
package body MC_Commissioning with SPARK_Mode is
   procedure Step (S : in out State; C : Command; E : Evidence; Status : out Outcome) is
      N : State := S;
      procedure Commit is begin N.Revision := N.Revision + 1; S := N; Status := OK; end Commit;
   begin
      Status := Conflict;
      if E.Expected_Revision /= S.Revision or else S.Revision = Counter'Last then return; end if;
      if C = Quarantine then N.Current := Quarantined; Commit; return; end if;
      case S.Current is
         when Uncommissioned =>
            if C = Record_Hardware and then E.Node_ID /= Zero_Identity and then E.Boot_ID /= Zero_Identity
              and then E.Hardware /= Zero_Digest and then E.Policy /= Zero_Digest
            then N.Node_ID:=E.Node_ID; N.Boot_ID:=E.Boot_ID; N.Hardware:=E.Hardware; N.Policy:=E.Policy;
               N.Current:=Hardware_Identified; Commit; end if;
         when Hardware_Identified =>
            if C=Record_Firmware and then E.Node_ID=S.Node_ID and then E.Firmware/=Zero_Digest
              and then E.Firmware_Authenticated and then E.Secure_Boot
            then N.Firmware:=E.Firmware; N.Current:=Firmware_Validated; Commit; end if;
         when Firmware_Validated =>
            if C=Enroll_Trust and then E.Node_ID=S.Node_ID and then E.Trust_Root/=Zero_Digest
              and then E.TPM_Owned and then E.New_Trust_Epoch>S.Trust_Epoch
            then N.Trust_Root:=E.Trust_Root; N.Trust_Epoch:=E.New_Trust_Epoch;
               N.Current:=Trust_Enrolled; Commit; end if;
         when Trust_Enrolled =>
            if C=Provision_Storage and then E.Storage_Layout/=Zero_Digest and then E.Disk_Encryption
            then N.Storage_Layout:=E.Storage_Layout; N.Current:=Storage_Provisioned; Commit; end if;
         when Storage_Provisioned =>
            if C=Provision_Recovery and then E.Recovery_Image/=Zero_Digest and then E.Recovery_Sealed
              and then E.Restore_Tested
            then N.Recovery_Image:=E.Recovery_Image; N.Current:=Recovery_Provisioned; Commit; end if;
         when Recovery_Provisioned =>
            if C=Install_Baseline and then E.Baseline/=Zero_Digest and then E.Baseline_Signed
            then N.Baseline:=E.Baseline; N.Current:=Baseline_Installed; Commit; end if;
         when Baseline_Installed =>
            if C=Verify_Baseline and then E.Baseline=S.Baseline and then E.Baseline_Attested
              and then E.Audit_Reachable
            then N.Current:=Baseline_Verified; Commit; end if;
         when Baseline_Verified =>
            if C=Admit_Cluster and then E.Cluster_Admission_Authorized and then E.Fencing_Ready
            then N.Current:=Cluster_Admitted; Commit; end if;
            if C=Finish and then not E.Cluster_Admission_Authorized then N.Current:=Commissioned; Commit; end if;
         when Cluster_Admitted =>
            if C=Finish and then E.Cluster_Admission_Authorized and then E.Fencing_Ready
            then N.Current:=Commissioned; Commit; end if;
         when Commissioned | Quarantined => null;
      end case;
   end Step;
end MC_Commissioning;
