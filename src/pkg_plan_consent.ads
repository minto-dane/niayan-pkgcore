-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Plan_Consent with SPARK_Mode, Pure is
   Offer_Size : constant := 160;
   Reply_Size : constant := 48;
   Maximum_Presentation : constant := 1_048_576;
   subtype Offer_Wire is Bytes (1 .. Offer_Size);
   subtype Reply_Wire is Bytes (1 .. Reply_Size);
   type Offer is record
      Request_ID, Boot_ID : Identity := Zero_Identity;
      Plan, Generation, Presentation : Digest := Zero_Digest;
      Deadline, Presentation_Size : Counter := 0;
   end record;
   type Choice is (Decline, Confirm);
   type Reply is record
      Offer_Digest : Digest := Zero_Digest;
      Decision : Choice := Decline;
   end record;
   function Valid (Value : Offer) return Boolean with Global => null;
   procedure Encode (Value : Offer; Wire : out Offer_Wire; Status : out Outcome)
     with Global => null;
   procedure Decode (Wire : Bytes; Value : out Offer; Status : out Outcome)
     with Global => null, Post => (if Status = OK then Valid (Value));
   procedure Encode_Reply (Value : Reply; Wire : out Reply_Wire; Status : out Outcome)
     with Global => null;
   procedure Decode_Reply (Wire : Bytes; Value : out Reply; Status : out Outcome)
     with Global => null;
   function Confirms (Value : Reply; Expected_Offer_Digest : Digest) return Boolean
     with Global => null;
   -- Canonical framing only. Expected_Offer_Digest is SHA-256 of the independently
   -- chosen complete Offer_Wire, not a digest copied from the received reply.
   -- The receiver must separately prove original peer/pidfd credentials, live
   -- boot/deadline, sealed presentation contents and one-use/full-life consent.
   -- This pure codec neither authenticates a user nor grants supply, operator,
   -- generation/publication/boot authority. It does not claim a human read the UI.
   -- Display language is outside the native plan/transaction identity. The
   -- particular UTF-8 presentation bytes are separately bound by Presentation.
end Pkg_Plan_Consent;
