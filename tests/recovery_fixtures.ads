-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Backups;
package Recovery_Fixtures with SPARK_Mode => Off is
   procedure Make (P : out MC_Backups.Policy; C : out MC_Backups.Catalog; Status : out Outcome);
   -- Public synthetic fixture metadata; never a storage or authority attestation.
end Recovery_Fixtures;
