-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Root_Identity with SPARK_Mode => Off is
   type Root_Identity is record
      Mount_ID, Inode : Wide := 0;
      Device_Major, Device_Minor : Word := 0;
   end record;
end Pkg_Root_Identity;
