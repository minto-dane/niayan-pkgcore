-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Maintenance with SPARK_Mode, Pure is
   type Hold_Kind is (Error_Hold, System_Hold, Security_Hold, Site_Hold, Compatibility_Hold);
   type Impact is (Live, Service_Restart, Node_Reboot, Data_Migration, Firmware_Change);
   type Hold is record
      Scope, Hold_ID : Identity := Zero_Identity;
      Policy, Subject, Reason : Digest := Zero_Digest;
      Serial, Published_At, Expires_At : Counter := 0;
      Kind : Hold_Kind := Error_Hold;
      Blocks_Apply, Blocks_Accept, Blocks_Commit : Boolean := True;
   end record;
   type Window is record
      Scope, Window_ID : Identity := Zero_Identity;
      Policy, Change_Set : Digest := Zero_Digest;
      Not_Before, Expires_At : Counter := 0;
      Maximum_Impact : Impact := Live;
      Emergency : Boolean := False;
      Operations_Approved, Security_Approved : Boolean := False;
   end record;
   function Valid (H : Hold) return Boolean with Global => null;
   function Valid (W : Window) return Boolean with Global => null;
   function Permits (W : Window; Now : Counter; Requested : Impact) return Boolean with Global => null;
   function Blocks (H : Hold; Subject : Digest; Apply, Accept_Change, Commit : Boolean) return Boolean with Global => null;
end MC_Maintenance;
