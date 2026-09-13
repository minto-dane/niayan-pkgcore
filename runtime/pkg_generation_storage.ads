-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_FS; with MC_Store; with Pkg_Root_State; with Pkg_File_Plan;
with Pkg_Generation_Descriptor; with Pkg_Generation_Manifest;
package Pkg_Generation_Storage with SPARK_Mode => Off is
   procedure Read_State (Root, State : MC_FS.Root; Expected_Root : Identity;
      RS : out Pkg_Root_State.State; Status : out Outcome);
   procedure Read_Plan (Store : MC_Store.Store; Hash : Digest;
      P : out Pkg_File_Plan.Plan; Status : out Outcome);
   procedure Read_Manifest (Store : MC_Store.Store; D : Pkg_Generation_Descriptor.Descriptor;
      M : out Pkg_Generation_Manifest.Manifest; Status : out Outcome);
   -- Internal storage decoding shared by reader and publisher. Callers retain
   -- their real root/publication/store reservations and validate accepted state,
   -- journal, complete retention and current authority separately. No grant.
end Pkg_Generation_Storage;
