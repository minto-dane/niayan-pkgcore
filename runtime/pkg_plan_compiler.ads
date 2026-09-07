-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_Plan_Compiler with SPARK_Mode=>Off is
   procedure Compile(Manifest_Directory, Output_Directory : String; Plan_Digest : out Digest; Status : out Outcome);
   -- Strict local source manifest to canonical plan.bin, not approval or a solver.
   -- Explicit pre/post images must be derived from authenticated package metadata
   -- and site effect contracts; the engine independently checks actual preimages.
end Pkg_Plan_Compiler;
