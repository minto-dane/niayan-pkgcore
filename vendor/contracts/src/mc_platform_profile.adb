-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Platform_Profile with SPARK_Mode is
   function Ready (F : Facts; Requested : Grade) return Boolean is
      Common : constant Boolean :=
        F.Policy /= Zero_Digest and then F.Accepted_Baseline /= Zero_Digest
        and then F.Secure_Boot and then F.Measured_Boot and then F.Signed_Kernel_Modules
        and then F.Kernel_Lockdown and then F.Integrity_Appraisal and then F.SELinux_Enforcing
        and then F.Audit_Remote_Sink and then F.Immutable_Audit_Receipt
        and then F.Kdump_Ready and then F.Kdump_Remote_Copy and then F.Pstore_Ready
        and then F.Hardware_Watchdog and then F.EDAC_RAS
        and then F.Storage_Health and then F.Storage_Scrub_Current
        and then F.Time_Integrity and then F.Power_Telemetry
        and then F.Recovery_Environment and then F.Tested_Backup_Restore
        and then F.Offsite_Backup and then F.Out_Of_Band_Management;
   begin
      case Requested is
         when Development =>
            return F.Policy /= Zero_Digest and then F.Accepted_Baseline /= Zero_Digest;
         when Qualified_Single_Node =>
            return Common;
         when Qualified_Cluster =>
            return Common and then F.Quorum and then F.Fencing
              and then F.Independent_Fault_Domains and then F.Cluster_Nodes >= 3
              and then F.Fault_Domains >= 3;
      end case;
   end Ready;
end MC_Platform_Profile;
