-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Checkpoint;
generic
   with procedure Authorize (Phase : String; Before, After : MC_Checkpoint.Descriptor;
      Status : out Outcome);
   with procedure Validate_State (D : MC_Checkpoint.Descriptor; Payload : Bytes;
      Status : out Outcome);
   with procedure Check_Anchor (D : MC_Checkpoint.Descriptor; Manifest : Digest;
      Status : out Outcome);
   with procedure Advance_Anchor (Before : Digest; D : MC_Checkpoint.Descriptor;
      Manifest : Digest; Status : out Outcome);
package MC_Checkpoint_Store with SPARK_Mode => Off is
   procedure Load (Directory : String; Root_ID, Stream_ID : Identity;
      D : out MC_Checkpoint.Descriptor; Payload : out Bytes; Used : out Natural;
      Status : out Outcome);
   procedure Publish (Directory : String; Expected : Digest;
      D : MC_Checkpoint.Descriptor; Payload : Bytes; Status : out Outcome);
   procedure Reconcile (Directory : String; Root_ID, Stream_ID : Identity;
      Status : out Outcome);
   -- Exact non-rollback anchor is external: Check_Anchor verifies the accepted
   -- generation AND digest, not just "generation >= minimum". Advance_Anchor must
   -- CAS Before -> Manifest using authenticated durable storage. Timeout is UNKNOWN.
   -- The snapshot validator must independently check unresolved operations and
   -- archive receipt authenticity before publishing. No default permissive hooks.
   -- This stores checkpoints; it does NOT truncate original journals or delete CAS.
   -- Orphan pending candidates are retained; an unanchored candidate requires
   -- explicit operator reconciliation, not a silently chosen old snapshot.
end MC_Checkpoint_Store;
