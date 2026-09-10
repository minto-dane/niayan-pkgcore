-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_FS; with Pkg_File_Plan;
package Pkg_Image_Inspector with SPARK_Mode=>Off is
   procedure Inspect(R : MC_FS.Root; Path : String; Maximum_Bytes : Counter;
      S : out Pkg_File_Plan.Shape; Read_Bytes : out Counter; Status : out Outcome);
   -- Read-only, fd-relative inspection. Checks identity before/after the read.
   -- Caller MUST exclude uncoordinated privileged writers; stat equality alone
   -- is not a security boundary against a malicious owner changing the object.
end Pkg_Image_Inspector;
