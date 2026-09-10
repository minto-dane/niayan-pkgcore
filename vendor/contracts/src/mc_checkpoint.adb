-- SPDX-License-Identifier: BSD-3-Clause
with MC_Codec; with MC_SHA256;
package body MC_Checkpoint with SPARK_Mode is
   use type Wide; use type Byte;
   Magic : constant Bytes := (77,67,67,72,75,48,48,49);
   function Valid (D : Descriptor) return Boolean is
     (D.Root_ID /= Zero_Identity and then D.Stream_ID /= Zero_Identity
      and then D.Contract /= Zero_Digest and then D.Payload /= Zero_Digest
      and then D.Generation > 0 and then D.Trust_Epoch > 0
      and then D.Payload_Size in 1 .. Max_Message and then D.Quiescent
      and then D.Audit_Receipt /= Zero_Digest
      and then (D.Covered_Records = 0 or else D.Log_Head /= Zero_Digest)
      and then ((D.Generation = 1 and then D.Previous = Zero_Digest)
        or else (D.Generation > 1 and then D.Previous /= Zero_Digest)));
   function Follows (Before, After : Descriptor; Before_Hash : Digest) return Boolean is
     (Valid (Before) and then Valid (After) and then Before_Hash /= Zero_Digest
      and then Before.Generation < Counter'Last
      and then After.Generation = Before.Generation + 1 and then After.Previous = Before_Hash
      and then After.Root_ID = Before.Root_ID and then After.Stream_ID = Before.Stream_ID
      and then After.Contract = Before.Contract
      and then After.Covered_Records >= Before.Covered_Records
      and then (After.Covered_Records /= Before.Covered_Records or else After.Log_Head = Before.Log_Head)
      and then After.Trust_Epoch >= Before.Trust_Epoch
      and then After.Replay_Epoch >= Before.Replay_Epoch
      and then After.Replay_Token >= Before.Replay_Token
      and then (After.Replay_Epoch > Before.Replay_Epoch
         or else After.Replay_Token > Before.Replay_Token
         or else After.Replay_Sequence >= Before.Replay_Sequence));
   function Encode (D : Descriptor) return Frame is
      B : Frame := (others => 0);
   begin
      B (1..8) := Magic; B (9..24) := D.Root_ID; B (25..40) := D.Stream_ID;
      B (41..72) := D.Contract; B (73..104) := D.Previous; B (105..136) := D.Payload;
      B (137..168) := D.Log_Head; B (169..200) := D.Audit_Receipt;
      MC_Codec.Put64 (B,201,Wide (D.Generation)); MC_Codec.Put64 (B,209,Wide (D.Covered_Records));
      MC_Codec.Put64 (B,217,Wide (D.Trust_Epoch)); MC_Codec.Put64 (B,225,Wide (D.Replay_Epoch));
      MC_Codec.Put64 (B,233,Wide (D.Replay_Token)); MC_Codec.Put64 (B,241,Wide (D.Replay_Sequence));
      MC_Codec.Put64 (B,249,Wide (D.Payload_Size)); B (257) := Boolean'Pos (D.Quiescent);
      B (289..320) := MC_SHA256.Hash (B (1..288)); return B;
   end Encode;
   procedure Decode (B : Bytes; D : out Descriptor; Status : out Outcome) is
      T : Descriptor;
   begin
      D := (others => <>); Status := Corrupt;
      if B'First /= 1 or else B'Length /= 320 then return; end if;
      if B (1..8) /= Magic or else B (257) > 1 then return; end if;
      for I in 0..6 loop
         if MC_Codec.U64 (B,201+I*8) > Wide (Counter'Last) then return; end if;
      end loop;
      T.Root_ID := B (9..24); T.Stream_ID := B (25..40); T.Contract := B (41..72);
      T.Previous := B (73..104); T.Payload := B (105..136); T.Log_Head := B (137..168);
      T.Audit_Receipt := B (169..200); T.Generation := Counter (MC_Codec.U64 (B,201));
      T.Covered_Records := Counter (MC_Codec.U64 (B,209)); T.Trust_Epoch := Counter (MC_Codec.U64 (B,217));
      T.Replay_Epoch := Counter (MC_Codec.U64 (B,225)); T.Replay_Token := Counter (MC_Codec.U64 (B,233));
      T.Replay_Sequence := Counter (MC_Codec.U64 (B,241)); T.Payload_Size := Counter (MC_Codec.U64 (B,249));
      T.Quiescent := B (257) = 1;
      if not Valid (T) or else Encode (T) /= B then return; end if; D := T; Status := OK;
   end Decode;
end MC_Checkpoint;
