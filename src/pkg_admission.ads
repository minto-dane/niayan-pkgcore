-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Admission with SPARK_Mode, Pure is
   type Facts is record
      Original_RPM_Digest : Digest := Zero_Digest;
      Authenticated_RPM_Digest : Digest := Zero_Digest;
      Contract_RPM_Digest : Digest := Zero_Digest;
      Contract_Digest : Digest := Zero_Digest;
      Repository_Epoch : Counter := 0;
      Minimum_Repository_Epoch : Counter := 0;
      Package_Signature_OK : Boolean := False;
      Metadata_Signature_OK : Boolean := False;
      Contract_Signature_OK : Boolean := False;
      Metadata_Fresh : Boolean := False;
      Key_Not_Revoked : Boolean := False;
      Schema_Supported : Boolean := False;
      Architecture_Allowed : Boolean := False;
      Distribution_Allowed : Boolean := False;
      Dependencies_Checked : Boolean := False;
      File_Collisions_Checked : Boolean := False;
      All_Script_And_Trigger_Effects_Covered : Boolean := False;
      Recovery_Content_Pinned : Boolean := False;
      Config_Migration_Checked : Boolean := False;
   end record;
   function Admissible (F : Facts) return Boolean with Global => null;
   -- Facts must be bound by the adapter to this exact immutable RPM descriptor,
   -- the existing inventory commitment, repository policy, and contract signature.
   -- This type is a specification boundary, not a network request format.
end Pkg_Admission;
