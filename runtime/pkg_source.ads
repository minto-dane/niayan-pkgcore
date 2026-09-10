-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Store; with MC_Signatures;
package Pkg_Source with SPARK_Mode => Off is
   procedure Fetch(Policy_Directory, Trust_State_Directory : String; Signed_Grant : Bytes;
      Signature : MC_Signatures.Signature; Deadline : Counter;
      Store : in out MC_Store.Store; RPM_Object : out Digest; Status : out Outcome);
   -- policy repo-<repository-id>.conf has exact fields: key,origin,contract,min-revision.
   -- Trust high-water state is separate from root rollback. No cross-origin redirects.
end Pkg_Source;
