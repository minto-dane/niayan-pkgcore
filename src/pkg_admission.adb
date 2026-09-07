-- SPDX-License-Identifier: MIT
package body Pkg_Admission with SPARK_Mode is
   function Admissible (F : Facts) return Boolean is
     (not Is_Zero (F.Original_RPM_Digest) and then not Is_Zero (F.Contract_Digest)
      and then F.Original_RPM_Digest = F.Authenticated_RPM_Digest
      and then F.Original_RPM_Digest = F.Contract_RPM_Digest
      and then F.Repository_Epoch >= F.Minimum_Repository_Epoch
      and then F.Package_Signature_OK and then F.Metadata_Signature_OK
      and then F.Contract_Signature_OK and then F.Metadata_Fresh
      and then F.Key_Not_Revoked and then F.Schema_Supported
      and then F.Architecture_Allowed and then F.Distribution_Allowed
      and then F.Dependencies_Checked and then F.File_Collisions_Checked
      and then F.All_Script_And_Trigger_Effects_Covered
      and then F.Recovery_Content_Pinned and then F.Config_Migration_Checked);
end Pkg_Admission;
