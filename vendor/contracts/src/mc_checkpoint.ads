-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Checkpoint with SPARK_Mode, Pure is
   type Descriptor is record
      Root_ID, Stream_ID : Identity := Zero_Identity;
      Contract, Previous, Payload, Log_Head, Audit_Receipt : Digest := Zero_Digest;
      Generation, Covered_Records, Trust_Epoch : Counter := 0;
      Replay_Epoch, Replay_Token, Replay_Sequence : Counter := 0;
      Payload_Size : Counter := 0;
      Quiescent : Boolean := False;
   end record;
   subtype Frame is Bytes (1 .. 320);
   function Valid (D : Descriptor) return Boolean with Global => null;
   function Follows (Before, After : Descriptor; Before_Hash : Digest) return Boolean
     with Global => null;
   function Encode (D : Descriptor) return Frame with Global => null;
   procedure Decode (B : Bytes; D : out Descriptor; Status : out Outcome) with Global => null;
   -- Snapshot must contain the COMPLETE replay window, pending-operation IDs,
   -- resource counters and all other application safety state. Quiescent=true
   -- must be established by a validator, never asserted by a remote packet.
   -- No proof of remote durability is inferred from Audit_Receipt being nonzero.
end MC_Checkpoint;
