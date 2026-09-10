-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Protocol;
package MC_Signatures with SPARK_Mode => Off is
   subtype Public_Key is Bytes (1 .. 32);
   subtype Signature is Bytes (1 .. 64);
   type Verified_Message is private;
   -- Signature is Ed25519 over Domain || canonical 160-byte header.
   -- The signed header commits to the entire body digest and all identities.
   -- Trusted_Key is a provisioned, scoped authority key, never a key from the packet.
   procedure Verify
     (Raw_Header : Bytes; Body_Data : Bytes; Sig : Signature;
      Trusted_Key : Public_Key; Message : out Verified_Message; Status : out Outcome);
   function Authenticated (Message : Verified_Message) return Boolean;
   function Content (Message : Verified_Message) return MC_Protocol.Header
     with Pre => Authenticated (Message);
private
   type Verified_Message is record
      Is_Verified : Boolean := False;
      Value : MC_Protocol.Header;
   end record;
end MC_Signatures;
