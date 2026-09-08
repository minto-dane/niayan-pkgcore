-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Backups;
package Pkg_Retention_Batch with SPARK_Mode, Pure is
   use type mc_backups.Selection;
   type Policy is record
      Recovery : MC_Backups.Policy;
      Minimum_Restore_Points : Positive range 1 .. MC_Backups.Capacity := 2;
      Minimum_Age : Counter := 86_400;
      Minimum_Recovery_Span : Counter := 0;
      -- Same trusted time unit as Recovery.Now_Lower/Now_Upper and Completed_At.
      -- Zero adds no span requirement. Restore points are distinct data positions,
      -- not duplicate manifests for an unchanged dataset. Time span uses the
      -- earliest retained validated completion for each distinct position.

      Catalog_Revision, Reference_Revision : Counter := 0;
      Complete_Reference_Scan, Writers_Quiescent, Audit_Export_Confirmed : Boolean := False;
   end record;
   procedure Plan (P : Policy; C : MC_Backups.Catalog; Count : Natural;
      Requested : MC_Backups.Selection; Delete_Set : out MC_Backups.Selection;
      Status : out Outcome) with Global => null,
      Post => (if Status /= OK then Delete_Set = (MC_Backups.Selection'(others => False)));
   -- ALL-OR-NOTHING batch admission. A chain ancestor, pinned/in-use object or
   -- retention-locked copy cannot be pruned. Remaining usable restore endpoints
   -- are recomputed after the ENTIRE proposed batch, not independently per file.
   -- Does not unlink files. Deletion adapter must CAS the exact catalog+reference
   -- revisions, recheck the control interlock and preserve a deletion receipt.
end Pkg_Retention_Batch;
