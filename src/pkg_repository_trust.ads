-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Repository_Trust with SPARK_Mode, Pure is
   type Metadata is record
      Repository_ID, Snapshot, Root_Keys : Digest := Zero_Digest;
      Repository_Epoch, Snapshot_Version, Timestamp_Version : Counter := 0;
      Produced_At, Expires_At : Counter := 0;
      Root_Signed, Snapshot_Signed, Timestamp_Signed : Boolean := False;
   end record;
   type Anchor is record
      Repository_ID, Root_Keys, Last_Snapshot : Digest := Zero_Digest;
      Minimum_Epoch, Minimum_Snapshot_Version, Minimum_Timestamp_Version : Counter := 0;
   end record;
   type Decision is (Trusted, Expired, Rollback, Wrong_Repository, Unauthenticated, Invalid);
   function Check (M : Metadata; A : Anchor; Now : Counter) return Decision with Global=>null;
end Pkg_Repository_Trust;
