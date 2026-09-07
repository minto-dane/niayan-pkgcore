-- SPDX-License-Identifier: MIT
package body MC_System_Baseline with SPARK_Mode is
   function Valid (B : Baseline) return Boolean is
     (B.ID/=Zero_Digest and then B.Distribution/=Zero_Digest and then B.Repository_Snapshot/=Zero_Digest
      and then B.Package_Incorporation/=Zero_Digest and then B.Kernel/=Zero_Digest
      and then B.Initramfs/=Zero_Digest and then B.Boot_Chain/=Zero_Digest
      and then B.Systemd_Profile/=Zero_Digest and then B.SELinux_Policy/=Zero_Digest
      and then B.Integrity_Policy/=Zero_Digest and then B.Configuration_Policy/=Zero_Digest
      and then B.Recovery_Image/=Zero_Digest and then B.Backup_Policy/=Zero_Digest
      and then B.Cluster_Policy/=Zero_Digest and then B.Trust_Roots/=Zero_Digest
      and then B.Repository_Epoch>0 and then B.Trust_Epoch>0 and then B.Security_Epoch>0
      and then B.Signed and then B.Independently_Approved and then B.Recovery_Verified);
   function Assess (B : Baseline; F : Running_Facts) return Assessment is
   begin
      if not Valid(B) then return Invalid_Baseline; end if;
      if F.Repository_Epoch<B.Repository_Epoch or else F.Trust_Epoch<B.Trust_Epoch
        or else F.Security_Epoch<B.Security_Epoch then return Rollback_Detected; end if;
      if F.Installed_Baseline/=B.ID or else F.Running_Kernel/=B.Kernel then return Baseline_Mismatch; end if;
      if F.Boot_Chain/=B.Boot_Chain then return Boot_Drift; end if;
      if F.Systemd_Profile/=B.Systemd_Profile or else F.SELinux_Policy/=B.SELinux_Policy
        or else F.Integrity_Policy/=B.Integrity_Policy or else F.Configuration_Policy/=B.Configuration_Policy
      then return Policy_Drift; end if;
      if not F.Package_Set_Exact then return Package_Drift; end if;
      if not F.Attestation_Trusted then return Unattested; end if;
      if not F.Recovery_Pinned then return Recovery_At_Risk; end if;
      return Conformant;
   end Assess;
end MC_System_Baseline;
