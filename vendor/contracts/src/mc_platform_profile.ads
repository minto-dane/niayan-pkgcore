-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Platform_Profile with SPARK_Mode, Pure is
   type Grade is (Development, Qualified_Single_Node, Qualified_Cluster);
   type Facts is record
      Secure_Boot, Measured_Boot, Signed_Kernel_Modules : Boolean := False;
      Kernel_Lockdown, Integrity_Appraisal, SELinux_Enforcing : Boolean := False;
      Audit_Remote_Sink, Immutable_Audit_Receipt : Boolean := False;
      Kdump_Ready, Kdump_Remote_Copy, Pstore_Ready, Hardware_Watchdog : Boolean := False;
      EDAC_RAS, Storage_Health, Storage_Scrub_Current : Boolean := False;
      Time_Integrity, Power_Telemetry : Boolean := False;
      Recovery_Environment, Tested_Backup_Restore, Offsite_Backup : Boolean := False;
      Out_Of_Band_Management : Boolean := False;
      Quorum, Fencing, Independent_Fault_Domains : Boolean := False;
      Cluster_Nodes, Fault_Domains : Natural range 0 .. 65_535 := 0;
      Policy, Accepted_Baseline : Digest := Zero_Digest;
   end record;
   function Ready (F : Facts; Requested : Grade) return Boolean with Global => null;
   -- Admission checklist only.  Every boolean must be produced by a qualified
   -- adapter bound to this exact node/baseline; it is not a self-attestation.
end MC_Platform_Profile;
