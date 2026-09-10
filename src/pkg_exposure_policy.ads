-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with Pkg_Advisory;
package Pkg_Exposure_Policy with SPARK_Mode, Pure is
   type Policy is record
      Critical_Max_Ms, Important_Max_Ms, Moderate_Max_Ms, Low_Max_Ms : Counter := 0;
      Exploited_Max_Ms : Counter := 0;
      Require_Fixed_Build, Require_Recovery_Pin : Boolean := True;
   end record;
   type Facts is record
      Advisory : Pkg_Advisory.Advisory;
      Now, First_Observed_At : Counter := 0;
      Fixed_Build_Available, Recovery_Pinned, Validation_Passed : Boolean := False;
   end record;
   type Status is (Within_Window, Due, Overdue, Blocked, No_Fix_Available);
   function Evaluate (P : Policy; F : Facts) return Status with Global => null;
end Pkg_Exposure_Policy;
