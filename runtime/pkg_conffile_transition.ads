-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Conffile_Transition with SPARK_Mode => Off is
   type File_Kind is (Missing, Regular, Other);
   type Image is record
      Kind : File_Kind := Missing;
      Content : Digest := Zero_Digest;
   end record;
   type Operation is (Install_Upgrade, Remove_Package, Purge_Package, Remove_On_Upgrade);
   type Choice is (Unresolved, Keep_Local, Use_Vendor);
   type Action is (Retain, Replace, Require_Choice, Delete, Backup_And_Delete);
   type Backup_Kind is (No_Backup, Local_Backup, Vendor_Backup);
   type Decision is record
      Effect : Action := Require_Choice;
      Content : Digest := Zero_Digest;
      Backup : Backup_Kind := No_Backup;
      Backup_Content : Digest := Zero_Digest;
      Next_Vendor : Image;
   end record;
   procedure Decide (Mode : Operation; Previously_Tracked : Boolean;
      Prior_Vendor, Current, Incoming : Image; Resolution : Choice;
      Result : out Decision; Status : out Outcome);
   -- Content identities are native SHA-256 CAS digests, never upstream MD5
   -- authorization. Missing is distinct from a regular empty file and from an
   -- unknown/unreadable object (Other). Both source and local changes, including
   -- local deletion, require a bound user choice; no automatic text merge.
   -- Result describes content and retained backup obligations, not filesystem
   -- effects or an execution grant. A Require_Choice result cannot be committed.
   -- The caller must authenticate original declarations, observe the exact local
   -- inode/attributes under reservation, retain all versions and bind the chosen
   -- decision to the complete managed plan. Link, ownership and generated config
   -- handling remain separate; Other is refused, never read as Missing.
end Pkg_Conffile_Transition;
