-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_System_Baseline with SPARK_Mode, Pure is
   type Baseline is record
      ID, Distribution, Repository_Snapshot, Package_Incorporation : Digest := Zero_Digest;
      Kernel, Initramfs, Boot_Chain, Systemd_Profile : Digest := Zero_Digest;
      SELinux_Policy, Integrity_Policy, Configuration_Policy : Digest := Zero_Digest;
      Recovery_Image, Backup_Policy, Cluster_Policy, Trust_Roots : Digest := Zero_Digest;
      Repository_Epoch, Trust_Epoch, Security_Epoch : Counter := 0;
      Signed, Independently_Approved, Recovery_Verified : Boolean := False;
   end record;
   type Running_Facts is record
      Installed_Baseline, Running_Kernel, Boot_Chain, Systemd_Profile : Digest := Zero_Digest;
      SELinux_Policy, Integrity_Policy, Configuration_Policy : Digest := Zero_Digest;
      Repository_Epoch, Trust_Epoch, Security_Epoch : Counter := 0;
      Attestation_Trusted, Package_Set_Exact, Recovery_Pinned : Boolean := False;
   end record;
   type Assessment is
     (Conformant, Invalid_Baseline, Baseline_Mismatch, Rollback_Detected,
      Boot_Drift, Policy_Drift, Package_Drift, Unattested, Recovery_At_Risk);
   function Valid (B : Baseline) return Boolean with Global=>null;
   function Assess (B : Baseline; F : Running_Facts) return Assessment with Global=>null;
end MC_System_Baseline;
