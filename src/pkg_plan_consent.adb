-- SPDX-License-Identifier: BSD-3-Clause
with MC_Codec;
package body Pkg_Plan_Consent with SPARK_Mode is
   Offer_Magic : constant Bytes (1 .. 8) := (78, 73, 65, 80, 76, 78, 48, 49);
   Reply_Magic : constant Bytes (1 .. 8) := (78, 73, 65, 67, 78, 83, 48, 49);
   function Valid (Value : Offer) return Boolean is
     (Value.Request_ID /= Zero_Identity and then Value.Boot_ID /= Zero_Identity
      and then Value.Plan /= Zero_Digest and then Value.Generation /= Zero_Digest
      and then Value.Presentation /= Zero_Digest
      and then Value.Deadline in 1 .. Counter'Last - 1
      and then Value.Presentation_Size in 1 .. Maximum_Presentation);

   procedure Encode (Value : Offer; Wire : out Offer_Wire; Status : out Outcome) is
   begin
      Wire := (others => 0); Status := Invalid_Input;
      if not Valid (Value) then return; end if;
      Wire (1 .. 8) := Offer_Magic; Wire (9 .. 24) := Value.Request_ID;
      Wire (25 .. 56) := Value.Plan; Wire (57 .. 88) := Value.Generation;
      Wire (89 .. 120) := Value.Presentation;
      MC_Codec.Put64 (Wire, 121, Wide (Value.Deadline));
      MC_Codec.Put64 (Wire, 129, Wide (Value.Presentation_Size));
      Wire (137 .. 152) := Value.Boot_ID;
      Status := OK;
   end Encode;

   procedure Decode (Wire : Bytes; Value : out Offer; Status : out Outcome) is
      B : Offer_Wire;
      Candidate : Offer;
      Deadline, Size : Wide;
   begin
      Value := (others => <>); Status := Invalid_Input;
      if Wire'Length /= Offer_Size then return; end if;
      B := Wire;
      if B (1 .. 8) /= Offer_Magic or else not Is_Zero (B (153 .. 160)) then return; end if;
      Deadline := MC_Codec.U64 (B, 121); Size := MC_Codec.U64 (B, 129);
      if Deadline not in 1 .. Wide (Counter'Last - 1) or else Size not in 1 .. Maximum_Presentation then return; end if;
      Candidate := (Request_ID => B (9 .. 24), Boot_ID => B (137 .. 152),
         Plan => B (25 .. 56), Generation => B (57 .. 88), Presentation => B (89 .. 120),
         Deadline => Counter (Deadline), Presentation_Size => Counter (Size));
      if not Valid (Candidate) then return; end if;
      Value := Candidate; Status := OK;
   end Decode;

   procedure Encode_Reply (Value : Reply; Wire : out Reply_Wire; Status : out Outcome) is
   begin
      Wire := (others => 0); Status := Invalid_Input;
      if Value.Offer_Digest = Zero_Digest then return; end if;
      Wire (1 .. 8) := Reply_Magic; Wire (9 .. 40) := Value.Offer_Digest;
      Wire (41) := Choice'Pos (Value.Decision);
      Status := OK;
   end Encode_Reply;

   procedure Decode_Reply (Wire : Bytes; Value : out Reply; Status : out Outcome) is
      B : Reply_Wire;
   begin
      Value := (others => <>); Status := Invalid_Input;
      if Wire'Length /= Reply_Size then return; end if;
      B := Wire;
      if B (1 .. 8) /= Reply_Magic or else Is_Zero (B (9 .. 40))
        or else B (41) not in 0 .. 1 or else not Is_Zero (B (42 .. 48)) then return; end if;
      Value := (Offer_Digest => B (9 .. 40), Decision => Choice'Val (B (41)));
      Status := OK;
   end Decode_Reply;

   function Confirms (Value : Reply; Expected_Offer_Digest : Digest) return Boolean is
     (Expected_Offer_Digest /= Zero_Digest and then Value.Decision = Confirm
      and then Value.Offer_Digest = Expected_Offer_Digest);
end Pkg_Plan_Consent;
