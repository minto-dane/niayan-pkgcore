-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Text; with Pkg_Versions;
package Pkg_EVR with SPARK_Mode, Pure is
   type EVR is record
      Epoch : Counter := 0;
      Version, Release : MC_Text.Value;
   end record;
   procedure Parse(S : String; V : out EVR; Status : out Outcome) with Global=>null;
   function Compare(A,B : EVR; Dependency_Match : Boolean:=False) return Pkg_Versions.Ordering with Global=>null;
   -- Dependency_Match omits release comparison if either side omits release.
   -- Versioned range-provides require a separate interval implementation; rejected.
end Pkg_EVR;
