-- SPDX-License-Identifier: MIT
package body Pkg_Activation with SPARK_Mode is
   function Evaluate (F : Facts) return Runtime_State is
   begin
      if F.Installed = Zero_Digest or else F.Accepted = Zero_Digest then return Activation_Failed; end if;
      if not F.Health_OK or else not F.Configuration_OK then return Activation_Failed; end if;
      if F.Migration_Pending or else (F.Required = Pkg_Advisory.Node_Reboot and then F.Reboot_Pending)
        or else F.Processes_Using_Old_Files > 0 or else F.Services_Pending > 0 or else F.Sessions_Pending > 0
      then return Partially_Active; end if;
      if F.Running = F.Installed then return Active; else return Installed_Not_Active; end if;
   end Evaluate;
end Pkg_Activation;
