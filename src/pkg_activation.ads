-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Pkg_Advisory;
package Pkg_Activation with SPARK_Mode, Pure is
   type Runtime_State is (Installed_Not_Active, Partially_Active, Active, Activation_Failed);
   type Facts is record
      Installed, Running, Accepted : Digest := Zero_Digest;
      Required : Pkg_Advisory.Activation := Pkg_Advisory.Immediate;
      Processes_Using_Old_Files : Counter := 0;
      Services_Pending, Sessions_Pending : Counter := 0;
      Reboot_Pending, Migration_Pending : Boolean := False;
      Health_OK, Configuration_OK : Boolean := False;
   end record;
   function Evaluate (F : Facts) return Runtime_State with Global => null;
   -- Installed, running and accepted versions are separate facts. Package apply
   -- never claims activation solely because filesystem replacement succeeded.
end Pkg_Activation;
