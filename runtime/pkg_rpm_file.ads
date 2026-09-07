-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_FS; with Pkg_RPM;
package Pkg_RPM_File with SPARK_Mode => Off is
   type Buffer is access Bytes;
   procedure Read_Headers(F : MC_FS.File; Data : out Buffer; M : out Pkg_RPM.Metadata; Status : out Outcome);
   procedure Free(Data : in out Buffer);
end Pkg_RPM_File;
