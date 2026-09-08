-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_Advisory with SPARK_Mode, Pure is
   type Severity is (None, Low, Moderate, Important, Critical);
   type Activation is (Immediate, New_Process, Service_Restart, Relogin, Node_Reboot, Offline_Migration);
   type Advisory is record
      ID, Package_ID, Fixed_Build, Metadata : Digest := Zero_Digest;
      Published_At, Security_Epoch : Counter := 0;
      Level : Severity := None;
      Activate : Activation := Immediate;
      Withdrawn, Known_Bad, Exploited, Data_Migration : Boolean := False;
   end record;
   type Decision is (No_Action, Schedule, Expedite, Block_Installation, Emergency_Change);
   function Valid (A : Advisory) return Boolean with Global => null;
   function Decide (A : Advisory; Installed : Digest; Policy_Epoch : Counter) return Decision with Global => null;
end Pkg_Advisory;
