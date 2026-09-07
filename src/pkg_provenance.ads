-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_Provenance with SPARK_Mode, Pure is
   type Level is (Unsigned, Signed_Source, Signed_Binary, Transparency_Bound, Reproducible_Witnessed);
   type Statement is record
      Package, Source, Build_Recipe, Builder, Repository, Receipt : Digest := Zero_Digest;
      Repository_Epoch, Build_Epoch : Counter := 0;
      Assurance : Level := Unsigned;
      Package_Signature, Metadata_Signature, Receipt_Verified : Boolean := False;
      Builder_Allowed, Source_Allowed, Recipe_Allowed : Boolean := False;
      Reproducible_Match : Boolean := False;
   end record;
   function Valid (S : Statement) return Boolean with Global => null;
   function Admissible (S : Statement; Minimum : Level; Minimum_Repository_Epoch : Counter) return Boolean
     with Global => null;
end Pkg_Provenance;
