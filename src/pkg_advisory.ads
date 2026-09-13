-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Advisory with SPARK_Mode, Pure is
   type Severity is (None, Low, Moderate, Important, Critical);
   type Activation is (Immediate, New_Process, Service_Restart, Relogin, Node_Reboot, Offline_Migration);
   type Advisory is record
      ID, Package_ID, Fixed_Build, Metadata : Digest := Zero_Digest;
      Reporting_Authority, Exploitation_Report_Record : Digest := Zero_Digest;
      Exploitation_Report_Published_At : Counter := 0;
      Exploitation_Report_Authenticated : Boolean := False;
      Published_At, Security_Epoch : Counter := 0;
      Level : Severity := None;
      Activate : Activation := Immediate;
      Withdrawn, Known_Bad, Authority_Reports_Wild_Exploitation, Data_Migration : Boolean := False;
   end record;
   -- Authority_Reports_Wild_Exploitation means a trusted authority reports observed
   -- exploitation in real-world operations (for example CISA KEV membership).
   -- It does NOT mean this node was attacked/compromised, nor that this installed
   -- build is applicable. False means no qualifying report in this observation,
   -- never proof of no exploitation. Record identity/source/date remain separate
   -- from this package advisory and any local incident or detection evidence.
   type Decision is (No_Action, Schedule, Expedite, Block_Installation, Emergency_Change);
   function Valid (A : Advisory) return Boolean with Global => null;
   function Decide (A : Advisory; Installed : Digest; Policy_Epoch : Counter) return Decision with Global => null;
end Pkg_Advisory;
