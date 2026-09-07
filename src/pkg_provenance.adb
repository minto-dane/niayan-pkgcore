-- SPDX-License-Identifier: MIT
package body Pkg_Provenance with SPARK_Mode is
   function Valid (S : Statement) return Boolean is
     (S.Package /= Zero_Digest and then S.Source /= Zero_Digest and then S.Build_Recipe /= Zero_Digest
      and then S.Builder /= Zero_Digest and then S.Repository /= Zero_Digest
      and then S.Repository_Epoch > 0 and then S.Build_Epoch > 0
      and then (if S.Assurance >= Transparency_Bound then S.Receipt /= Zero_Digest and then S.Receipt_Verified)
      and then (if S.Assurance = Reproducible_Witnessed then S.Reproducible_Match));
   function Admissible (S : Statement; Minimum : Level; Minimum_Repository_Epoch : Counter) return Boolean is
     (Valid (S) and then S.Assurance >= Minimum and then S.Repository_Epoch >= Minimum_Repository_Epoch
      and then S.Package_Signature and then S.Metadata_Signature
      and then S.Builder_Allowed and then S.Source_Allowed and then S.Recipe_Allowed
      and then (if Minimum >= Transparency_Bound then S.Receipt_Verified)
      and then (if Minimum = Reproducible_Witnessed then S.Reproducible_Match));
end Pkg_Provenance;
