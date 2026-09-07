-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Tools; with MC_Store;
package Pkg_RPM_Auth with SPARK_Mode => Off is
   procedure Verify(T : MC_Tools.Tool; Private_Keyring : String;
      Store : MC_Store.Store; RPM_Digest : Digest; Deadline : Counter; Status : out Outcome);
   -- Native rpmkeys is deliberately in TCB, not falsely labelled proven. Enforces
   -- _pkgverify_level all, dedicated pre-provisioned keyring and an actual signature
   -- tag. Exact held RPM descriptor is inherited at fd 4; no mutable path handoff.
   -- Never imports keys from an RPM/repository, never disables GPG/digest checks.
end Pkg_RPM_Auth;
